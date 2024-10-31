import naclPkg from 'tweetnacl';
import { Scoped } from './variables';
import { Buffer } from 'buffer';
import { simplifyError } from 'simplify-error';
import { dirname } from 'path';
import { mkdir } from 'fs/promises';

const { box, randomBytes } = naclPkg;

export const getRandomString = (length = 20, number = true, capLetter = true, smallLetter = true) => {
    const randomChars = `${capLetter ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : ''}${smallLetter ? 'abcdefghijklmnopqrstuvwxyz' : ''}${number ? '0123456789' : ''}`;

    return Array(length).fill(0).map(() => randomChars.charAt(Math.round(Math.random() * randomChars.length))).join('');
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

export const deserializeE2E = (data, projectName) => {
    try {
        const [clientPubKey, clientNonce, clientData] = data.split('.'),
            [_, serverPrivateKey] = Scoped.InstancesData[projectName].E2E_BufferPair || [];

        if (!serverPrivateKey) throw '"e2eKeyPair" is required for decrypting an end-to-end messages';
        const baseArray = box.open(
            Buffer.from(clientData, 'base64'),
            Buffer.from(clientNonce, 'base64'),
            Buffer.from(clientPubKey, 'base64'),
            serverPrivateKey
        );
        if (!baseArray) throw 'The server was unable to decrypt the reqest body';

        const decryptedData = JSON.parse(Buffer.from(baseArray).toString('utf8'));

        return [decryptedData[0], clientPubKey, decryptedData[1]];
    } catch (e) {
        throw simplifyError('decryption_failed', `${e}`);
    }
};

export const serializeE2E = (message, clientPublicKey, projectName) => {
    const nonce = randomBytes(box.nonceLength),
        nonceBase64 = Buffer.from(nonce).toString('base64');

    const [_, serverPrivateKey] = Scoped.InstancesData[projectName].E2E_BufferPair || [];

    return `${nonceBase64}.${Buffer.from(
        box(
            Buffer.from(JSON.stringify([
                message
            ]), 'utf8'),
            nonce,
            Buffer.from(clientPublicKey, 'base64'),
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