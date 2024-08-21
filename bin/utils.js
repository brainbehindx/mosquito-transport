import { isAbsolute, join, resolve } from 'path';
import { createCipheriv, createDecipheriv, createHash } from 'node:crypto';

export const one_mb = 1024 * 1024,
    one_gb = one_mb * 1024;

export const BLOCKS_IDENTIFIERS = {
    DB_URL: '--->[DB_URL]:',
    DB_NAME: '--->[DB_NAME]:',
    COLLECTION: '--->[COL]:',
    DOCUMENT: '--->[DOC]:',
    STORAGE_DIRECTORY: '--->[DIR]:',
    STORAGE_FILE_PATH: '--->[FILE_PATH]:',
    STORAGE_FILE: '--->[FILE]:'
};

export const BIN_CONFIG_FILE = 'mosquito.config.js';
export const DEFAULT_DELIMITER = 'MOSQUITO_TRANSPORT_DELIMITER';
export const RESERVED_DB = ['admin', 'local', 'config'];

export const isRelative = p => typeof p === 'string' && (p.startsWith('./') || p.startsWith('../'));
export const isPath = (p) => typeof p === 'string' && (isAbsolute(p) || isRelative(p));
const tipPath = p => ['/', '../', './'].find(v => p.startsWith(v));

export const resolvePath = (...p) => {
    const paths = [...p];

    return isRelative(paths[0])
        ? resolve(process.cwd(), `${tipPath(paths[0])}${join(...paths)}`)
        : join(...paths);
}
export const isHttp_s = t => typeof t === 'string' && (t.startsWith('http://') || t.startsWith('https://'));

export function isValidDbName(name) {
    const maxLength = 64;
    const invalidChars = /[\/\\ "$\0]/;

    return typeof name === 'string' &&
        name.length > 0 &&
        name.length <= maxLength &&
        !invalidChars.test(name);
}

export function isValidColName(name) {
    const maxLength = 120;
    const invalidChars = /\0/;

    return typeof name === 'string' &&
        name.length > 0 &&
        name.length <= maxLength &&
        !invalidChars.test(name) &&
        !name.startsWith('system.');
}

const algorithm = 'aes-256-cbc';

const hashPassword = password => {
    return [
        createHash('sha256').update(password).digest('base64').substring(0, 32),
        createHash('md5').update(password).digest('base64').substring(0, 16)
    ];
};

// Encrypt function
export function encryptData(data, password) {
    const [key, iv] = hashPassword(password);
    const cipher = createCipheriv(algorithm, key, iv);
    return Buffer.concat([
        cipher.update(data),
        cipher.final()
    ]);
}

// Decrypt function
export function decryptData(data, password) {
    const [key, iv] = hashPassword(password);

    const decipher = createDecipheriv(algorithm, key, iv);
    return Buffer.concat([
        decipher.update(data),
        decipher.final()
    ]);
}