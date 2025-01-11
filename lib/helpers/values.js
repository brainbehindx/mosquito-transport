import { Scoped } from "./variables";
import { join } from 'path';
import { simplifyError } from 'simplify-error';

export const DEFAULT_DB = Symbol('default_db');
export const ADMIN_DB_NAME = Symbol('admin_db_name');
export const ADMIN_DB_URL = Symbol('admin_db');

export const AUTH_PROVIDER_ID = {
    GOOGLE: 'google',
    FACEBOOK: 'facebook',
    PASSWORD: 'password',
    TWITTER: 'x',
    GITHUB: 'github',
    APPLE: 'apple'
};

export const one_day = 86400000,
    one_week = 604800000,
    one_month = 2419200000,
    one_year = one_month * 12,
    one_hour = 3600000,
    one_minute = 60000;

export const one_mb = 1048576;

export const STORAGE_ROUTE = '/storage';
export const STORAGE_DIRS = (projectName) => ({
    FILES: join(STORAGE_PREFIX_PATH(projectName), '.files'),
    VID_CACHER: join(STORAGE_PREFIX_PATH(projectName), '.vid_cacher'),
    HASH_LINK: join(STORAGE_PREFIX_PATH(projectName), '.hash/links'),
    HASH_GROUPING: join(STORAGE_PREFIX_PATH(projectName), '.hash/grouping'),
    PENDING_HASH_LOG: join(STORAGE_PREFIX_PATH(projectName), '.hash/pending.log'),
    // FILE_HASH_PLACEMENT: join(STORAGE_PREFIX_PATH(projectName), '.hash/placement'),
    HASH_FILE: join(STORAGE_PREFIX_PATH(projectName), '.hash/files')
});

export const STORAGE_PREFIX_PATH = (projectName) => join(Scoped.InstancesData[projectName].dumpsterPath || process.cwd(), projectName);

export const TOKEN_EXPIRY = (projectName) => (Scoped.InstancesData[projectName].accessTokenInterval || one_hour);
export const REFRESH_TOKEN_EXPIRY = (projectName) => (Scoped.InstancesData[projectName]?.refreshTokenExpiry || one_year);

export const NO_CACHE_HEADER = {
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
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

export const EnginePath = {
    userAcct: 'userAcct',
    tokenStore: 'tokenStore',
    refreshTokenStore: 'refreshTokenStore'
};

export const ERRORS = {
    INCORRECT_ACCESS_KEY: simplifyError('incorrect_access_key', 'The accessKey been provided is not correct'),
    TOO_MANY_REQUEST: simplifyError('too_many_request', 'Making too many requests, wait a moment and try again later'),
    DISABLE_FEATURE: simplifyError('disabled_feature', 'This feature was disabled by the administrators'),
    // auth
    INCORRECT_PASSWORD: simplifyError('incorrect_password', 'The provided password for this account is incorrect'),
    CONCURRENT_SIGNUP: simplifyError('pending_signup', 'Email address is currently being signup elsewhere'),
    PASSWORD_REQUIRED: simplifyError('password_required', 'Password cannot be empty'),
    INVALID_EMAIL: simplifyError('invalid_email', 'Provided email address is invalid'),
    EMAIL_ALREADY_EXIST: simplifyError('email_already_exists', 'Email address already exists'),
    USER_NOT_FOUND: simplifyError('user_not_found', 'This user is not found on our database records'),
    ACCOUNT_NO_PASSWORD: simplifyError('incorrect_password', 'The provided password for this account is incorrect'),
    UID_ALREADY_EXISTS: uid => simplifyError('uid_already_exists', `This userId (${uid}) for this account has already been taken`),
    ACCOUNT_DISABLED: simplifyError('account_disabled', 'You cannot sign into this account because it has been disabled'),
    TOKEN_MISMATCH: simplifyError('token_mismatch', 'The accessToken and refreshToken are not meant for each other'),
    ENTITY_MISMATCH: simplifyError('entity_mismatch', 'This accessToken does not belong to the provided refreshToken'),
    TOKEN_USER_NOT_FOUND: simplifyError('token_user_not_found', 'The user that owns this token was not found on our database records'),
    TOKEN_ACCOUNT_DISABLED: simplifyError('token_account_disabled', 'You cannot refresh token for this account because it has been disabled'),
    GOOGLE_AUTH_DISABLED: simplifyError(
        'google_auth_disabled',
        'You haven\'t enable google auth yet, provide the "googleAuthConfig" in MosquitoTransportServer() constructor to enable this feature'
    ),
    GOOGLE_AUTH_FAILED: simplifyError('google_auth_failed', 'This user could not be authenticate'),
    GOOGLE_TOKEN_EXPIRED: simplifyError('google_auth_token_expired', 'The google token provided has already expired'),
    // STORAGE
    FILE_TOO_BIG: (max) => simplifyError('file_too_big', `Uploaded file exceeded the maximum allowed size ${max} btyes`),
    // tokens
    TOKEN_EXPIRED: simplifyError('token_expired', 'The provided token has already expired'),
    TOKEN_NOT_FOUND: simplifyError('token_not_found', 'This token was not found in our records'),
    TOKEN_MOCKED: simplifyError('token_mismatch', 'This token has been tempered with or probably mocked'),
    // apis
    ENCRYPTION_REQUIRED: simplifyError('encryption_required', 'All request sent to this endpoint must be encrypted'),
    UNAUTHORIZED_ACCESS: simplifyError('unauthorize_access', 'Only authorized users can access this request'),
    UNVERIFIED_EMAIL: simplifyError('unverified_email', 'User email is not verified, Please verify and try again'),
    DISABLED_AUTH_ACCESS: simplifyError('disabled_auth', 'This request does not accept disabled auth')
};