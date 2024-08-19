import { isAbsolute, resolve } from 'path';
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
export const resolvePath = p => isRelative(p) ? resolve(process.cwd(), p) : p;

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
export function encryptData(text, password) {
    const [key, iv] = hashPassword(password);
    const cipher = createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Decrypt function
export function decryptData(encryptedText, password) {
    const [key, iv] = hashPassword(password);

    const decipher = createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}