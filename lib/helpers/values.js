export const DEFAULT_DB_NAME = 'DEFAULT_DB';
export const DEFAULT_DB_URL = 'mongodb://127.0.0.1:27017';

export const ADMIN_DB_NAME = 'ADMIN_DB';
export const ADMIN_DB_URL = 'mongodb://127.0.0.1:7777';

export const DEFAULT_STORAGE_PATH = '';
export const BACKUP_STORAGE_PATH = '';

export const TOKEN_EXPIRY = () => 86400000 + Date.now();

export const REGEX = {
    LINK_REGEX: /(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig,
    EMAIL_REGEX: /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
    USERNAME_REGEX: /^[a-zA-Z0-9](_(?!(\.|_))|\.(?!(_|\.))|[a-zA-Z0-9]){2,30}[a-zA-Z0-9]$/,
    PHONE_NUMBER: /^[+]?[\s./0-9]*[(]?[0-9]{1,4}[)]?[-\s./0-9]*$/g,
    NAME: /^[a-zA-Z ]{3,50}$/,
}