import LimitTask from "limit-task";
import naclPkg from 'tweetnacl-functional';
import { availableParallelism } from 'os';
import { Worker } from "worker_threads";
const { NACL } = naclPkg;

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
    const worker = new Worker(workerCode, {
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

    const queue = LimitTask(9);

    return (type, params) => queue(() =>
        new Promise((resolve, reject) => {
            const session = `${++ite}`;

            resolution[session] = [resolve, reject];
            worker.postMessage({ type, params, session });
        })
    );
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

export default {
    encrypt: (bufferData, clientPublicKey, serverPrivateKey) => {
        return addTask('encrypt', [bufferData, clientPublicKey, serverPrivateKey]);
    },
    decrypt: (data, nonce, clientPubKey, serverPrivateKey) => {
        return addTask('decrypt', [data, nonce, clientPubKey, serverPrivateKey]);
    }
};