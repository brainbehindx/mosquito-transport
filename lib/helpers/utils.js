import naclPkg from 'tweetnacl-functional';
import { Scoped } from './variables.js';
import { Buffer } from 'buffer';
import { simplifyError } from 'simplify-error';
import { dirname } from 'path';
import { mkdir } from 'fs/promises';
import e2e_worker from './e2e_worker.js';
import { deserialize, serialize } from 'entity-serializer';

const { box, randomBytes } = naclPkg;

export const getRandomString = (length = 20, number = true, capLetter = true, smallLetter = true) => {
    const randomChars = `${capLetter ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : ''}${number ? '0123456789' : ''}${smallLetter ? 'abcdefghijklmnopqrstuvwxyz' : ''}`;
    const indexSize = randomChars.length - 1;

    return Array(length).fill(0).map(() => randomChars.charAt(Math.round(Math.random() * indexSize))).join('');
};

export const normalizeRoute = (route = '') => route.split('').map((v, i, a) =>
    ((!i && v === '/') || (i === a.length - 1 && v === '/') || (i && a[i - 1] === '/' && v === '/')) ? '' : v
).join('');

export const ensureDir = async (filepath) => {
    filepath = `/${normalizeRoute(filepath)}`;
    await niceMkdir(dirname(filepath));
    return filepath;
};

const niceMkdir = async dir => {
    try {
        await mkdir(dir, { recursive: true, force: true });
    } catch (_) { }
};

export const niceTry = (promise) => new Promise(async resolve => {

    try {
        const r = await promise();
        resolve(r);
    } catch (e) {
        console.error('niceTry encounter an error: ', e);
        resolve();
    }
});

export const serializeEntity = obj => serialize(obj);

export const deserializeEntity = deserialize;

export const deserializeE2E = async (data = '', projectName) => {
    try {
        const [clientPubKey, clientNonce, clientData] = data.split('.').map(v => new Uint8Array(Buffer.from(v, 'base64'))),
            [_, serverPrivateKey] = Scoped.InstancesData[projectName].E2E_BufferPair || [];

        if (!serverPrivateKey) throw '"e2eKeyPair" is required for decrypting an end-to-end messages';

        let baseArray;

        if (clientData.byteLength > 10240) {
            baseArray = await e2e_worker.decrypt(clientData, clientNonce, clientPubKey, serverPrivateKey);
        } else baseArray = box.open(clientData, clientNonce, clientPubKey, serverPrivateKey);

        if (!baseArray) throw 'The server was unable to decrypt the request body';

        const decryptedData = JSON.parse(Buffer.from(baseArray).toString('utf8'));

        return [decryptedData[0], clientPubKey, decryptedData[1]];
    } catch (e) {
        throw simplifyError('decryption_failed', `${e}`);
    }
};

export const serializeE2E = async (message, clientPublicKey, projectName) => {
    const [_, serverPrivateKey] = Scoped.InstancesData[projectName].E2E_BufferPair || [];
    const inputData = new Uint8Array(Buffer.from(JSON.stringify([message]), 'utf8'));

    if (inputData.byteLength > 10240) {
        const { data, nonce } = await e2e_worker.encrypt(inputData, clientPublicKey, serverPrivateKey);
        return `${Buffer.from(nonce).toString('base64')}.${Buffer.from(data).toString('base64')}`;
    }

    const nonce = randomBytes(box.nonceLength),
        nonceBase64 = Buffer.from(nonce).toString('base64');

    return `${nonceBase64}.${Buffer.from(
        box(
            inputData,
            nonce,
            clientPublicKey,
            serverPrivateKey
        )
    ).toString('base64')}`;
};

export const getStringExtension = (url) => {
    const r = url.split(/[#?]/)[0].split(".").pop().trim();
    return r === url ? '' : r;
};

export const interpolate = (x, [y1, x1], [y2, x2]) => {
    return y1 + ((x - x1) * ((y2 - y1) / (x2 - x1)));
};

export const encodeBinary = (s) => Buffer.from(s, 'utf8').toString('base64');
export const decodeBinary = (s) => Buffer.from(s, 'base64').toString('utf8');