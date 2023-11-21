export const DEFAULT_DB_NAME = 'DEFAULT_DB';
export const DEFAULT_DB_URL = 'mongodb://127.0.0.1:27017';

export const ADMIN_DB_NAME = 'ADMIN_DB';
export const ADMIN_DB_URL = DEFAULT_DB_URL || 'mongodb://127.0.0.1:7777';

export const DEFAULT_STORAGE_PATH = '';
export const BACKUP_STORAGE_PATH = '';

export const one_day = 86400000,
    one_week = 604800000,
    one_month = 2419200000,
    one_hour = 3600000;

export const one_mb = 1048576;

export const STORAGE_ROUTE = '/storage';

export const STORAGE_URL_TO_FILE = (url = '', projectName) => url.split(STORAGE_ROUTE).map((v, i) => i ? v : STORAGE_PATH(projectName)).join('');

export const STORAGE_PATH = (projectName) => `${process.cwd()}/.dump/${projectName}`; //.split('/').filter((_, i, a) => i !== a.length - 1).join('/');

export const TOKEN_EXPIRY = () => one_hour + Date.now();

export const REGEX = {
    LINK_REGEX: /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig,
    EMAIL_REGEX: /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
    USERNAME_REGEX: /^[a-zA-Z0-9](_(?!(\.|_))|\.(?!(_|\.))|[a-zA-Z0-9]){2,30}[a-zA-Z0-9]$/,
    PHONE_NUMBER: /^[+]?[\s./0-9]*[(]?[0-9]{1,4}[)]?[-\s./0-9]*$/g,
    NAME: /^[a-zA-Z ]{3,50}$/,
}

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
    _invalidateToken: '_invalidateToken',
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
}