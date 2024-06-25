import naclPkg from 'tweetnacl';
import { Scoped } from './variables';

const { box, randomBytes } = naclPkg;

export const simplifyError = (error, message) => ({
    simpleError: { error, message }
});

export const simplifyCaughtError = (e) => e?.simpleError ? e : simplifyError('unexpected_error', `${e}`);

export const getRandomString = (length = 20, number = true, capLetter = true, smallLetter = true) => {
    const randomChars = `${capLetter ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : ''}${smallLetter ? 'abcdefghijklmnopqrstuvwxyz' : ''}${number ? '0123456789' : ''}`;

    return Array(length).fill(0).map(() => randomChars.charAt(Math.round(Math.random() * randomChars.length))).join('');
}

export const IS_RAW_OBJECT = (e) => e && typeof e === 'object' && !Array.isArray(e);

export const IS_JSON_OBJECT = (o) => o !== null &&
    typeof o === 'object' &&
    (Object.prototype.toString.call(o) === '[object Object]' ||
        Object.prototype.toString.call(o) === '[object Array]' ||
        Array.isArray(o));

export const IS_WHOLE_NUMBER = (v) => typeof v === 'number' && !`${v}`.includes('.');

export const queryEntries = (obj, lastPath = '', exceptions = [], seperator = '.') => {
    let o = [];

    Object.entries(obj).forEach(([key, value]) => {
        if (IS_RAW_OBJECT(value) && !exceptions.includes(key)) {
            o = [...o, ...queryEntries(value, `${lastPath}${key}${seperator}`, exceptions, seperator)];
        } else o.push([`${lastPath}${key}`, value]);
    });

    return o;
}

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

        if (!serverPrivateKey) throw '"e2eKeyPair" is required for decrypting a e2e messages';
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
}

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
}

export const requestURL = (request) => {
    return new URL(request.url, `http://${request.headers.host}`);
}

export const getStringExtension = (url) => {
    const r = url.split(/[#?]/)[0].split(".").pop().trim();
    return r === url ? '' : r;
}

export const interpolate = (x, [y1, x1], [y2, x2]) => {
    return y1 + ((x - x1) * ((y2 - y1) / (x2 - x1)));
}

export const encodeBinary = (s) => Buffer.from(s, 'utf8').toString('base64');
export const decodeBinary = (s) => Buffer.from(s, 'base64').toString('utf8');