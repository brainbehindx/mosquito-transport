import { Scoped } from "./variables";
import { join } from 'path';

export const DEFAULT_DB = Symbol('default_db');
export const ADMIN_DB_NAME = Symbol('admin_db_name');
export const ADMIN_DB_URL = Symbol('admin_db');

export const DEFAULT_STORAGE_PATH = '';
export const BACKUP_STORAGE_PATH = '';

export const one_day = 86400000,
    one_week = 604800000,
    one_month = 2419200000,
    one_hour = 3600000,
    one_minute = 60000;

export const one_mb = 1048576;

export const STORAGE_ROUTE = '/storage';

export const STORAGE_URL_TO_FILE = (link = '', projectName) => {
    try {
        const url = new URL(link);
        if (!url) throw '';
        return `${STORAGE_PATH(projectName)}${url.pathname.substring(STORAGE_ROUTE.length)}`;
    } catch (e) {
        return null;
    }
}

export const STORAGE_PATH = (projectName) => `${STORAGE_PREFIX_PATH(projectName)}/.dump/${projectName}`;
export const STORAGE_PREFIX_PATH = (projectName) => `${Scoped.InstancesData[projectName].dumpsterPath || process.cwd()}`;
export const STORAGE_FREEZER_DIR = (projectName) => join(STORAGE_PREFIX_PATH(projectName), '.vid_freezer');

export const TOKEN_EXPIRY = (projectName) => (Scoped.InstancesData[projectName].accessTokenInterval || one_hour);
export const REFRESH_TOKEN_EXPIRY = (projectName) => (Scoped.InstancesData[projectName]?.refreshTokenExpiry || one_month);

export const REGEX = {
    LINK_REGEX: () => /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig,
    EMAIL: () => ({
        test: (t) => typeof t === 'string' &&
            /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(t) &&
            !!t.trim() &&
            t.trim().length <= 1000
    }),
    USERNAME_REGEX: () => /^[a-zA-Z0-9](_(?!(\.|_))|\.(?!(_|\.))|[a-zA-Z0-9]){2,30}[a-zA-Z0-9]$/,
    PHONE_NUMBER: () => /^[+]?[\s./0-9]*[(]?[0-9]{1,4}[)]?[-\s./0-9]*$/g,
    NAME: () => ({ test: (t) => typeof t === 'string' && !!t.trim() && t.trim().length <= 500 })
};

export const EngineRoutes = {
    _listenUserVerification: '_listenUserVerification',
    _customSignin: '_customSignin',
    _customSignup: '_customSignup',
    _refreshAuthToken: '_refreshAuthToken',
    _googleSignin: '_googleSignin',
    _appleSignin: '_appleSignin',
    _facebookSignin: '_facebookSignin',
    _twitterSignin: '_twitterSignin',
    _githubSignin: '_githubSignin',
    _signOut: '_signOut',
    _uploadFile: '_uploadFile',
    _deleteFile: '_deleteFile',
    _deleteFolder: '_deleteFolder',
    _listenCollection: '_listenCollection',
    _listenDocument: '_listenDocument',
    _startDisconnectWriteTask: '_startDisconnectWriteTask',
    _cancelDisconnectWriteTask: '_cancelDisconnectWriteTask',
    _readDocument: '_readDocument',
    _queryCollection: '_queryCollection',
    _writeDocument: '_writeDocument',
    _writeMapDocument: '_writeMapDocument',
    _documentCount: '_documentCount',
    _areYouOk: '_areYouOk'
};