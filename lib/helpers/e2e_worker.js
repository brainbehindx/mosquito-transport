import LimitTask from "limit-task";
import naclPkg from 'tweetnacl-functional';
import { availableParallelism } from 'os';
import { Worker } from "worker_threads";
import { Scoped } from './variables.js';
import { simplifyError } from 'simplify-error';
import { deserialize, serialize } from 'entity-serializer';

const { NACL, box, randomBytes } = naclPkg;

function e2e_baseCode() {
    const serializeE2E = (data, clientPublicKey, serverPrivateKey) => {
        const nonce = randomBytes(box.nonceLength);

        return {
            data: box(data, nonce, clientPublicKey, serverPrivateKey),
            nonce
        };
    };

    const deserializeE2E = (data, nonce, clientPubKey, serverPrivateKey) => {
        const result = box.open(data, nonce, clientPubKey, serverPrivateKey);

        if (!result) throw 'Decrypting e2e message failed';
        return result;
    };

    parentPort.on('message', function (data) {

        try {
            let response;
            if (data.type === 'encrypt') {
                response = serializeE2E(...data.params);
            } else if (data.type === 'decrypt') {
                response = deserializeE2E(...data.params);
            }
            parentPort.postMessage([response, data.session]);
        } catch (error) {
            parentPort.postMessage([undefined, undefined, { error }]);
        }
    });
}

const workerCode = `
   const { parentPort } = require('worker_threads');

   const NACL_PKG = ${NACL.toString()};
   const naclPkg = {};

   NACL_PKG(naclPkg);

   const { box, randomBytes } = naclPkg;

   const baseCode = ${e2e_baseCode.toString()};
   baseCode();
`;

const spawnWorker = () => {
    const resolution = {};
    let ite = 0;
    let closureError;

    const worker =
        new Worker(workerCode, {
            execArgv: ['--no-deprecation'],
            eval: true
        });

    // Receive the result from the worker
    worker.on('message', function (event) {
        const [response, session, error] = event;
        if (error) {
            resolution[session][1](error.error);
        } else {
            resolution[session][0](response);
        }
        delete resolution[session];
    });

    const rejectPendingTasks = () => {
        const pendTasks = Object.entries(resolution);
        for (const [session, [_, reject]] of pendTasks) {
            delete resolution[session];
            reject(closureError?.error);
        }

        if (pendTasks.length) setTimeout(rejectPendingTasks, 90);

        for (let i = 0; i < e2e_engines.length; i++) {
            const thatCallback = e2e_engines[i];

            if (thatCallback === callback) {
                e2e_engines.splice(i, 1);
                currentTask = 0;
                break;
            }
        }
    };

    worker.on('error', err => {
        closureError = { error: err };
        rejectPendingTasks(err);
    });

    worker.on('exit', () => {
        if (!closureError) closureError = {};
        rejectPendingTasks();
    });

    const queue = LimitTask(9);

    const callback = (type, params) =>
        queue(() =>
            new Promise((resolve, reject) => {
                const session = `${++ite}`;

                resolution[session] = [resolve, reject];
                worker.postMessage({ type, params, session });
            })
        );

    return callback;
};

let currentTask = -1;
const e2e_engines = [];

const MAX_WORKERS = Math.max(availableParallelism(), 7);

const addTask = (type, params) => {
    if (++currentTask >= e2e_engines.length) {
        if (e2e_engines.length < MAX_WORKERS) {
            // spawn new engine on demand
            e2e_engines.push(spawnWorker());
        } else currentTask = 0;
    }
    return e2e_engines[currentTask](type, params);
}

const thisEncrypt = (bufferData, clientPublicKey, serverPrivateKey) => {
    return addTask('encrypt', [bufferData, clientPublicKey, serverPrivateKey]);
};

const thisDecrypt = (data, nonce, clientPubKey, serverPrivateKey) => {
    return addTask('decrypt', [data, nonce, clientPubKey, serverPrivateKey]);
};

const FALLBACK_SIZE = 10240;

const deserializeE2E = async (data, projectName) => {
    try {
        const [clientPubKey, clientNonce, clientData] = deserialize(data);
        const [_, serverPrivateKey] = Scoped.InstancesData[projectName].E2E_BufferPair || [];

        if (!serverPrivateKey) throw '"e2eKeyPair" is required for decrypting an end-to-end messages';

        let baseArray;

        if (clientData.byteLength > FALLBACK_SIZE) {
            baseArray = await thisDecrypt(clientData, clientNonce, clientPubKey, serverPrivateKey);
        } else baseArray = box.open(clientData, clientNonce, clientPubKey, serverPrivateKey);

        if (!baseArray) throw 'The server was unable to decrypt the request body';

        const decryptedData = deserialize(baseArray);

        return [decryptedData[0], clientPubKey, decryptedData[1]];
    } catch (e) {
        throw simplifyError('decryption_failed', `${e}`);
    }
};

const serializeE2E = async (message, clientPublicKey, projectName) => {
    const [_, serverPrivateKey] = Scoped.InstancesData[projectName].E2E_BufferPair || [];
    const inputData = serialize(message);

    if (inputData.byteLength > FALLBACK_SIZE) {
        const { data, nonce } = await thisEncrypt(inputData, clientPublicKey, serverPrivateKey);
        return serialize([nonce, data]);
    }

    const nonce = randomBytes(box.nonceLength);

    return serialize([
        nonce,
        box(
            inputData,
            nonce,
            clientPublicKey,
            serverPrivateKey
        )
    ]);
};

export default {
    encrypt: serializeE2E,
    decrypt: deserializeE2E
}