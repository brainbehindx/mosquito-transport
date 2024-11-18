import { Db, Document, MongoClient, MongoClientOptions, SortDirection, UpdateDescription } from "mongodb";
import express from "express";
import { CorsOptions } from "cors";
import { Sort } from "mongodb";
import { Filter } from "mongodb";
import { UpdateFilter } from "mongodb";
import type { IncomingHttpHeaders } from "http";
import type { ParsedUrlQuery } from "querystring";
import { Socket } from "socket.io";
import { TokenPayload } from "google-auth-library";
import { Transform, PassThrough } from "stream";

interface SimpleError {
    simpleError?: {
        error: string;
        message: string;
    }
}

interface GeneralObject {
    [key: string]: any
}

interface PureHttpRequest extends express.Request {
    res: undefined
}

interface StorageRulesSnapshot {

}

type WriteScope = 'setOne' | 'setMany' | 'updateOne' | 'updateMany' | 'mergeOne' | 'mergeMany' | 'deleteOne' | 'deleteMany' | 'replaceOne' | 'putOne';

interface BatchUpdateValue {
    scope: WriteScope;
    find?: DatabaseRulesIOPrescription['find'];
    value?: DatabaseRulesIOPrescription['value'];
    path: string;
}

interface DatabaseRulesIOPrescription {
    path?: string;
    direction?: SortDirection;
    sort?: Sort;
    limit?: number;
    random?: boolean;
    find?: Filter<undefined> | {} | undefined;
    value?: UpdateFilter<undefined> | undefined;
    config?: PrescriptionConfig | undefined;
    scope?: WriteScope;
}

interface PrescribedExtraction {
    collection: string;
    sort?: Sort;
    direction?: SortDirection;
    limit?: number;
    find?: Filter<undefined> | {} | undefined;
    findOne?: Filter<undefined> | {} | undefined;
    returnOnly?: string | string[] | undefined;
    excludeFields?: string | string[] | undefined;
}

interface PrescriptionConfig {
    extraction?: PrescribedExtraction | PrescribedExtraction[] | undefined;
    returnOnly?: string | string[] | undefined;
    excludeFields?: string | string[] | undefined;
}

interface DatabaseRulesBatchWritePrescription {
    value: BatchUpdateValue[];
    stepping?: boolean;
}

interface DatabaseRulesSnapshot {
    headers: IncomingHttpHeaders;
    auth?: JWTAuthData | undefined;
    endpoint: '_readDocument' | '_queryCollection' | '_writeDocument' | '_writeMapDocument' | '_documentCount' | '_listenCollection' | '_listenDocument' | '_startDisconnectWriteTask' | '_cancelDisconnectWriteTask';
    prescription?: DatabaseRulesIOPrescription | DatabaseRulesBatchWritePrescription;
    dbName?: string;
    dbRef?: string;
}

type LogLevel = 'all' | 'auth' | 'database' | 'storage' | 'external-requests' | 'served-content' | 'database-snapshot' | 'error';

interface GoogleAuthConfig {
    clientID?: string;
}

interface AppleAuthConfig {

}

interface FacebookAuthConfig {

}

interface GithubAuthConfig {

}

interface TwitterAuthConfig {

}

interface FallbackAuthConfig {

}

interface RawObject {
    [key: string]: any
}

interface SneakSignupAuthConfig {
    email?: string;
    password?: string;
    photo?: string;
    name?: string;
    metadata: RawBodyRequest;
    token?: string;
    request: express.Request;
    method: auth_provider_id_values;
    providerData?: TokenPayload;
}

interface StaticContentProps {
    /**
     * Enable or disable accepting ranged requests, defaults to true.
     * Disabling this will not send Accept-Ranges and ignore the contents of the Range request header.
     */
    acceptRanges?: boolean | undefined;

    /**
     * Enable or disable setting Cache-Control response header, defaults to true.
     * Disabling this will ignore the maxAge option.
     */
    cacheControl?: boolean | undefined;

    /**
     * Set how "dotfiles" are treated when encountered.
     * A dotfile is a file or directory that begins with a dot (".").
     * Note this check is done on the path itself without checking if the path actually exists on the disk.
     * If root is specified, only the dotfiles above the root are checked (i.e. the root itself can be within a dotfile when when set to "deny").
     * 'allow' No special treatment for dotfiles.
     * 'deny' Send a 403 for any request for a dotfile.
     * 'ignore' Pretend like the dotfile does not exist and 404.
     * The default value is similar to 'ignore', with the exception that this default will not ignore the files within a directory that begins with a dot, for backward-compatibility.
     */
    dotfiles?: "allow" | "deny" | "ignore" | undefined;

    /**
     * Byte offset at which the stream ends, defaults to the length of the file minus 1.
     * The end is inclusive in the stream, meaning end: 3 will include the 4th byte in the stream.
     */
    end?: number | undefined;

    /**
     * Enable or disable etag generation, defaults to true.
     */
    etag?: boolean | undefined;

    /**
     * If a given file doesn't exist, try appending one of the given extensions, in the given order.
     * By default, this is disabled (set to false).
     * An example value that will serve extension-less HTML files: ['html', 'htm'].
     * This is skipped if the requested file already has an extension.
     */
    extensions?: string[] | string | boolean | undefined;

    /**
     * Enable or disable the immutable directive in the Cache-Control response header, defaults to false.
     * If set to true, the maxAge option should also be specified to enable caching.
     * The immutable directive will prevent supported clients from making conditional requests during the life of the maxAge option to check if the file has changed.
     * @default false
     */
    immutable?: boolean | undefined;

    /**
     * By default send supports "index.html" files, to disable this set false or to supply a new index pass a string or an array in preferred order.
     */
    index?: string[] | string | boolean | undefined;

    /**
     * Enable or disable Last-Modified header, defaults to true.
     * Uses the file system's last modified value.
     */
    lastModified?: boolean | undefined;

    /**
     * Provide a max-age in milliseconds for http caching, defaults to 0.
     * This can also be a string accepted by the ms module.
     */
    maxAge?: string | number | undefined;

    /**
     * Serve files relative to path.
     */
    root?: string | undefined;

    /**
     * Byte offset at which the stream starts, defaults to 0.
     * The start is inclusive, meaning start: 2 will include the 3rd byte in the stream.
     */
    start?: number | undefined;
}

interface SneakSignupAuthResult {
    metadata?: AuthData['metadata'];
    profile?: AuthData['profile'];
    uid?: string;
}

interface MSocketHandshake {
    /**
     * The headers sent as part of the handshake
     */
    headers: IncomingHttpHeaders;
    /**
     * The date of creation (as string)
     */
    time: string;
    /**
     * The ip of the client
     */
    address: string;
    /**
     * Whether the connection is cross-domain
     */
    xdomain: boolean;
    /**
     * Whether the connection is secure
     */
    secure: boolean;
    /**
     * The date of creation (as unix timestamp)
     */
    issued: number;
    /**
     * The request URL string
     */
    url: string;
    /**
     * The query object
     */
    query: ParsedUrlQuery;
    /**
     * The user that made this request
     */
    user?: Promise<AuthData>;
    /**
     * The auth object
     */
    auth: {
        [key: string]: any;
    };
    /**
     * the access token of the user that initiated this handshake
     * 
     * N/B: make sure to always revalidate this when making sensitive request
     */
    userToken: string | undefined;
}

interface MSocketSnapshot {
    on: Socket['on'];
    once: Socket['once'];
    prependOnceListener: Socket['prependOnceListener'];
    handshake: MSocketHandshake;
    emit: Socket['emit'];
    emitWithAck: Socket['emitWithAck'];
    timeout: (timeout: number) => ({
        emitWithAck: Socket['emitWithAck'];
    })
}

interface MSocketError {
    error: string;
    message: string;
    socket: Socket;
}

interface TransformMediaOption {
    uri: string;
    request?: express.Request;
}

interface TransformMediaRoute {
    route: typeof RegExp | string;
    transformAs?: 'image' | 'video';
    transform: (options: TransformMediaOption) => Buffer | string | null | undefined;
}

interface MongoInstances {
    defaultName?: string;
    instance: MongoClient;
}

interface MongoInstancesMap {
    [key: 'default' | 'admin' | string]: MongoInstances;
}

interface UserMountedEvent {
    /**
     * the user object mounted
     */
    user: AuthData;
    /**
     * The headers sent as part of the handshake
     */
    headers: IncomingHttpHeaders;
}

interface DDOS_Limiter {
    calls: number;
    perSeconds: number;
}

interface AuthDDOS extends DDOS_Limiter {
    signup?: DDOS_Limiter;
    signin?: DDOS_Limiter;
    signout?: DDOS_Limiter;
    refresh_token?: DDOS_Limiter;
    google_signin?: DDOS_Limiter;
}

interface DatabaseDDOS extends DDOS_Limiter {
    read?: DDOS_Limiter;
    query?: DDOS_Limiter;
    write?: DDOS_Limiter;
}

interface StorageDDOS extends DDOS_Limiter {
    get?: DDOS_Limiter;
    upload?: DDOS_Limiter;
    delete?: DDOS_Limiter;
    delete_folder?: DDOS_Limiter;
}

interface ApiDDOS {
    [key: string]: DDOS_Limiter;
}

interface DDOS_Map {
    auth?: AuthDDOS;
    database?: DatabaseDDOS;
    storage?: StorageDDOS;
    requests?: ApiDDOS | DDOS_Limiter;
}

interface MosquitoServerConfig {
    /**
     * the name for your mosquito-transport instance. this is required and used internally by both the backend and frontend client
     */
    projectName: string;
    /**
     * a 90 character string which is used in signing jwt access and refresh token
     */
    signerKey: string;

    storageRules: (snapshot?: StorageRulesSnapshot) => Promise<void> | undefined;
    databaseRules: (snapshot?: DatabaseRulesSnapshot) => Promise<void> | undefined;
    onSocketSnapshot?: (snapshot?: MSocketSnapshot) => void;
    onSocketError?: (error?: MSocketError) => void;
    /**
     * the port number you want mosquito-transport instance to be running on
     */
    port?: number;
    /**
     * true if you want new users to be assign a sequential `uid` like 0, 1, 2, 3, 4, 5, ...,
     * 
     * Please note: this is an experimental feature
     */
    enableSequentialUid?: boolean;
    /**
     * a random string used by the frontend client for accessing internal resources
     */
    accessKey: string;
    /**
     * can either be a string or array containing any of the following:
     * 
     * - `all`: log all requests
     * - `auth`: log authentication requests
     * - `database`: log database requests
     * - `storage`: log storage requests
     * - `external-requests`: log api requests
     * - `served-content`: log storage GET requests
     * - `database-snapshot`: log database snapshot events
     * - `error`: log all internal errors
     * 
     * @default `error`
     */
    logger?: LogLevel | LogLevel[];
    /**
     * true to deserialize BSON values emited at {@link MosquitoServerConfig.databaseRules} to their Node.js closest equivalent types
     * 
     * @default true
     */
    castBSON: boolean;
    /**
     * this prevent ddos attack on this server instance by rate limiting request made to specific endpoint base on client ip address.
     * 
     * the default value prevent ddos attack to auth endpoint as follows:
     * 
     * ```json
     * {
     *   "auth": {
     *     "signup": { "calls": 7, "perSeconds": 1800 },
     *     "signin": { "calls": 10, "perSeconds": 600 },
     *     "google_signin": { "calls": 7, "perSeconds": 300 }
     *   }
     * }
     * ```
     */
    ddosMap: DDOS_Map;
    /**
     * disable remote client access to internal functionalities
     * 
     * by default all internal functionalities are enabled for remote client
     */
    internals?: {
        auth: boolean;
        database: boolean;
        storage: boolean;
    };
    /**
     * this should be a valid http or https link. it is used internally while signing jwt and for prefixing storage `downloadUrl` when uploading a file by frontend client
     */
    externalAddress?: string;
    /**
     * if no `externalAddress` was provided, `externalAddress` will be a construct as follows:
     * 
     * ```js
     * `http://${hostname || 'localhost'}:${port}`
     * ```
     */
    hostname?: string;
    /**
     * an object that maps names to your mongodb instance. if no `dbRef` were provided, the `default` mongodb instance will be used.
     * 
     * ```js
     * import MosquitoTransportServer from "mosquito-transport";
     * import { MongoClient } from 'mongodb';
     * 
     * // create a mongodb instance
     * const dbInstance = new MongoClient('mongodb://127.0.0.1:27017');
     * dbInstance.connect();
     * 
     * const remoteInstance = new MongoClient('mongodb://other-searver.com');
     * remoteInstance.connect();
     * 
     * const serverApp = new MosquitoTransportServer({
     *   ...otherProps,
     *   mongoInstances: {
     *     // frontend client are prohitted from accessing this instance
     *     admin: {
     *        instance: dbInstance,
     *        defaultName: 'ADMIN_DB_NAME'
     *     },
     *     // this will be the default db if no dbRef was provided by the frontend client
     *     default: {
     *        instance: dbInstance,
     *        defaultName: 'DEFAULT_DB_NAME'
     *     },
     *     // additional instance
     *     remoteBackup: {
     *         instance: remoteInstance,
     *        defaultName: 'WEB_BACKUP'
     *     }
     *   }
     * });
     * 
     * // then you can access this via frontend client
     * 
     * const webInstance = new MosquitoTransport({
     *   projectUrl: 'http://localhost:4534/app_name',
     *   accessKey: 'some_unique_string',
     *   ...options
     * });
     * 
     * webInstance.getDatabase(
     *   // if this is undefined, the server will use `defaultName` as the default name
     *   'database_name',
     *   // the name of the mongoInstances map
     *   'remoteBackup'
     * ).collection('transactions').findOne({ date: { $gt: 1719291129937 } }).get();
     * 
     * // or access the default db
     * 
     * webInstance.getDatabase().collection('testing');
     * ```
     */
    mongoInstances: MongoInstancesMap;
    /**
     * true if you want to threat the same email address from different auth provider as a single user
     */
    mergeAuthAccount?: boolean;
    transformMediaRoute?: '*' | TransformMediaRoute[];
    /**
     * This is the numbers of milliseconds to cache the transformed video media file before it is deleted. This is basically to avoid the overhead processing time next time the frontend client tries to access it. Defaults to 7 hours.
     */
    transformMediaCleanupTimeout?: number;
    /**
     * 
     * a function use in preventing signup and adding metadata before signup
     * @example
     * ```js
     * import MosquitoTransportServer, { AUTH_PROVIDER_ID } from "mosquito-transport";
     * const blacklisted_country = ['RU', 'AF', 'NG'];
     * 
     * const serverApp = new MosquitoTransportServer({
     *     ...otherProps,
     *     sneakSignupAuth: ({ request, email, name, password, method }) => {
     *         const geo = lookupIpAddress(request.ip);
     *         if (!geo) throw 'Failed to lookup request location';
     *         if (blacklisted_country.includes(geo.country))
     *             throw 'This platform is not yet available in your location';
     *         
     *         if (method === AUTH_PROVIDER_ID.PASSWORD && password.length < 5)
     *             throw 'password is too short';
     *         const uid = randomString(11),
     *             lang = getCountryLang(geo?.country || 'US');
     *         return Promise.resolve({
     *             metadata: {
     *                 country: geo.country,
     *                 city: geo.city,
     *                 location: geo.ll,
     *                 tz: geo?.timezone,
     *                 ip: request.ip,
     *                 locale: 'en'
     *             },
     *             uid
     *         });
     *     }
     * });
     * ```
     */
    sneakSignupAuth?: (config: SneakSignupAuthConfig) => Promise<SneakSignupAuthResult>;
    /**
     * a function that is called when a user's mosquito client sdk is authenticated and online
     * 
     * @example
     * ```js
     * import MosquitoTransportServer from "mosquito-transport";
     * 
     * const serverApp = new MosquitoTransportServer({
     *     ...otherProps,
     *     onUserMounted: ({ user, headers }) => {
     *         // update the user online status
     *         serverApp.collection('users').updateOne({ _id: user.uid }, { 
     *             status: 'online',
     *             onlineOn: Date.now()  
     *          });
     * 
     *         return () => {
     *             // update the user offline status
     *             serverApp.collection('users').updateOne({ _id: user.uid }, {
     *                 status: Date.now(),
     *                 offlineOn: Date.now() 
     *             });
     *         }
     *     }
     * });
     * ```
     * 
     * @returns a function that is called when the user goes offline
     */
    onUserMounted?: (config: UserMountedEvent) => () => void;
    googleAuthConfig?: GoogleAuthConfig;
    appleAuthConfig?: AppleAuthConfig;
    facebookAuthConfig?: FacebookAuthConfig;
    githubAuthConfig?: GithubAuthConfig;
    twitterAuthConfig?: TwitterAuthConfig;
    fallbackAuthConfig?: FallbackAuthConfig;
    staticContentProps?: StaticContentProps;
    staticContentMaxAge?: number;
    staticContentCacheControl?: number;
    corsOrigin?: CorsOptions;
    maxRequestBufferSize?: number;
    maxUploadBufferSize?: number;
    uidLength?: number;
    accessTokenInterval?: number;
    refreshTokenExpiry?: number;
    dumpsterPath?: string;
    /**
     * require an e2e public and private key like:
     * `['public key', 'private key']`
     */
    e2eKeyPair?: string[] | undefined;
    enforceE2E?: boolean;
    /**
     * this will be the first middleware that will be executed for all incoming http request to this mosquito-transport instance.
     * 
     * You may intercept this middleware to manage and prevent ddos attack and handle some custom route such as `favicon.ico`
     */
    preMiddlewares?: express.Handler | express.Handler[];
}

interface UserProfile {
    email?: string,
    name?: string,
    photo?: string,
    phoneNumber?: string,
    bio?: string
}

interface AuthData {
    email?: string;
    metadata: RawObject;
    signupMethod: auth_provider_id_values;
    currentAuthMethod: auth_provider_id_values;
    joinedOn: number;
    uid: string;
    claims: RawObject;
    emailVerified: boolean;
    tokenID: string;
    disabled: boolean;
    entityOf: string;
    profile: {
        photo: string;
        name: string;
    },
    exp: number;
    aud: string;
    iss: string;
    sub: string;
}

interface RefreshTokenData {
    uid: string;
    tokenID: string;
    isRefreshToken: true;
}

interface UserData extends AuthData {
    password?: string;
}

interface JWTAuthData extends AuthData {
    token: string;
}

interface NewUserAuthData extends AuthData {
    'google.com': string;
    'facebook.com': string;
    'x.com': string;
    'github.com': string;
    'apple.com': string;
}

interface MosquitoHttpOptions {
    /**
     * reject request that doesn't have a token or have invalid tokens
     */
    enforceUser?: boolean;
    /**
     * admits all request that doesn't have a token or have a token that is valid
     */
    validateUser?: boolean;
    /**
     * reject request if the sent token does not have a verified email address
     */
    enforceVerifiedUser?: boolean;
    /**
     * disable all internal adds-on such as token validation, end-to-end encryption
     * 
     * this is basically identical to calling `MtInstance.express.use((req, res, next)=> { })`
     */
    rawEntry?: boolean;
}

interface DatabaseListenerOption {
    includeBeforeData?: boolean;
    includeAfterData?: boolean;
    pipeline?: { pipeline?: Document[] }
}

interface DatabaseListenerCallbackData {
    insertion?: { _id: string };
    deletion?: string;
    update?: UpdateDescription,
    before?: Document,
    after?: Document,
    timestamp: number,
    auth?: AuthData | undefined,
    operation: 'insert' | 'delete' | 'update';
    documentKey: string;
}

interface WriteCommand {

}

interface DisconnectTaskInspector extends SimpleError {
    status?: 'completed' | 'error' | 'cancelled';
    committed?: boolean;
    task?: ({
        commands: WriteCommand;
        dbName?: string;
        dbRef?: string;
    })
}

interface StorageSnapshot {
    uri: string;
    dest: string;
    operation: 'uploadFile' | 'deleteFile' | 'deleteFolder';
    auth?: JWTAuthData;
}

interface RawBodyRequest extends express.Request {
    rawBody: Buffer;
}

/**
 * useful for avoiding encrypting data and extra overhead
 */
export class DoNotEncrypt {
    value: any;
}

export default class MosquitoTransportServer {
    constructor(config: MosquitoServerConfig);

    /**
     * the directory where storage files are saved
     */
    get storagePath(): string;

    /**
     * quickly get an end-to-end encryption pair key for your server
     * @returns [public_string, private_string]
     */
    get sampleE2E(): string[];

    get express(): express.Application;

    getDatabase(dbName?: string, dbRef?: string): Db;

    /**
     * purge all tokens references for a user and sign-out the user immediately
     * @param uid uid of the user you are signing out
     */
    signOutUser(uid: string): Promise<void>;

    /**
     * parse jwt token
     */
    parseToken(token: string): AuthData;

    /**
     * verify token to check if it was trully created using signerKey without checking against the expiry or local token reference
     * 
     * @param token - the token to be verified
     * @param isRefreshToken - set this to true if token is a refresh token
     */
    verifyToken(token: string, isRefreshToken?: boolean): Promise<AuthData>;

    /**
     * verify token to check if it was trully created using signerKey and checking against the expiry and local token reference
     * 
     * @param token - the token to be validated
     * @param isRefreshToken - set this to true if token is a refresh token
     */
    validateToken(token: string, isRefreshToken?: boolean): Promise<AuthData | RefreshTokenData>;

    /**
     * remove local reference of a token
     * 
     * @param token - the token to be invalidated
     * @param isRefreshToken - set this to true if token is a refresh token
     */
    invalidateToken(token: string, isRefreshToken?: boolean): Promise<void | boolean>;

    /**
     * listen to incoming request
     */
    listenHttpsRequest(route: string, callback?: (request: RawBodyRequest, response: express.Response, auth?: JWTAuthData | null) => void, options?: MosquitoHttpOptions): void;
    /**
     * listen to insert, update and delete events from mongodb
     */
    listenDatabase(collection: string, callback?: (data: DatabaseListenerCallbackData) => void, options?: DatabaseListenerOption): void;
    /**
     * listen to storage event. these event are typically made by the frontend client.
     */
    listenStorage(callback?: (snapshot: StorageSnapshot) => void): () => void;
    /**
     * get the local source where a file is stored on the disk
     * @param path the location of the file
     */
    getStorageSource(path: string): { source: string, hashValue?: string } | null;
    /**
     * stream a file to the storage directory and optionally create hash for it to reduce duplicate file storage
     * 
     * @param destination the location to store the file to
     * @param createHash optionally create hash for this write to save disk space
     * @param callback function that is called when the stream encounter an error or succeed
     */
    createWriteStream(destination: string, createHash: undefined | boolean, callback: (err: Error, url: string) => void): PassThrough;
    /**
     * write a file to the storage directory and optionally create hash for it to reduce duplicate file storage
     * 
     * @param destination the location to store the file to
     * @param buffer the file's buffer content
     * @param createHash optionally create hash for this write to save disk space
     */
    writeFile(destination: string, buffer: Buffer, createHash?: boolean): Promise<string>;
    /**
     * delete file in the storage directory
     * @param path the location to the file
     */
    deleteFile(path: string): Promise<void>;
    /**
     * delete folder in the storage directory
     * @param path the location to the file
     */
    deleteFolder(path: string): Promise<void>;
    /**
     * listen to new user
     * @param callback event called when a new user creates an account on this Server Instance
     */
    listenNewUser(callback?: (user: NewUserAuthData) => void): void;
    /**
     * listen to deletedUser
     * @param callback event called when a user account was deleted on this Server Instance
     */
    listenDeletedUser(callback?: (uid: string) => void): void;
    inspectDocDisconnectionTask(callback?: (data: DisconnectTaskInspector) => void): void;
    updateUserProfile(uid: string, profile: UserProfile): Promise<void>;
    updateUserMetadata(uid: string, metadata: GeneralObject): Promise<void>;
    updateUserClaims(uid: string, claims: RawObject): Promise<void>;
    updateUserEmailAddress(uid: string, email: string): Promise<void>;
    updateUserPassword(uid: string, password: string): Promise<void>;
    updateUserEmailVerify(uid: string, verified: boolean): Promise<void>;
    disableUser(uid: string, disable: boolean): Promise<void>;
    getUserData(uid: string): Promise<UserData>;

    /**
     * extract storage and database backup of this `MosquitoTransport` instance
     * 
     * @example
     * ```js
     * import MosquitoTransportServer from "mosquito-transport";
     * 
     * const serverApp = new MosquitoTransportServer({
     *     ...otherProps
     * });
     * 
     * const stream = createWriteStream('./backup.bin');
     * 
     * serverApp.extractBackup().pipe(stream);
     * 
     * ```
     * 
     * it is recommended to extract backup from the cli while no MosquitoTransport
     * instance is running as to avoid inconsistency in the extracted data
     * 
     * @returns `Transform` stream to read from
     */
    extractBackup(config?: BackupExtraction): Transform;

    /**
     * install backup content from a source to the respective destination
     * 
     * it is recommended to install backup from the cli while no MosquitoTransport
     * instance is running as to avoid inconsistency in data installation
     * 
     * @returns a promise
     */
    installBackup(): Promise<BackupInstallationResult>;
}

interface BackupInstallationResult {
    database: {
        [dbUrl: string]: {
            [dbName: string]: number;
        }
    },
    totalWrittenDocuments: number;
    totalWrittenFiles: number;
}

interface BackupExtraction {
    /**
     * password use for encrypting the backup data
     */
    password?: string | undefined;
    /**
     * this callback should be handled when you to pass option to the internal `MongoClient` constructor used in extracting mongodb.
     * 
     * you can also return your own `MongoClient` to be use in extracting mongodb
     * 
     * @returns `MongoClient` or `MongoClientOptions`
     */
    onMongodbOption?: (dbUrl: string) => MongoClientOptions | MongoClient;
}

interface BackupInstallation {
    password?: string | undefined;
    /**
     * this callback should be handled when you to pass option to the internal `MongoClient` constructor used in extracting mongodb.
     * 
     * you can also return your own `MongoClient` to be use in extracting mongodb
     * 
     * @returns `MongoClient` or `MongoClientOptions`
     */
    onMongodbOption?: (dbUrl: string) => BackupRemapMongoOption | MongoClient;
}

interface BackupRemapMongoOption extends MongoClientOptions {
    /**
     * when installing a backup, this can be used to remap database location
     */
    url?: string | undefined;
}

type longitude = number;
type latitude = number;

export function GEO_JSON(latitude: latitude, longitude: longitude): {
    type: "Point",
    coordinates: [longitude, latitude],
};

export function FIND_GEO_JSON(coordinates: [latitude, longitude], offSetMeters: number, centerMeters?: number): {
    $nearSphere: {
        $geometry: {
            type: "Point",
            coordinates: [longitude, latitude]
        },
        $minDistance: number | 0,
        $maxDistance: number
    }
};

export const AUTH_PROVIDER_ID: auth_provider_id;

interface auth_provider_id {
    GOOGLE: 'google.com';
    FACEBOOK: 'facebook.com';
    PASSWORD: 'password';
    TWITTER: 'x.com';
    GITHUB: 'github.com';
    APPLE: 'apple.com';
}

type auth_provider_id_values = auth_provider_id['GOOGLE'] |
    auth_provider_id['FACEBOOK'] |
    auth_provider_id['PASSWORD'] |
    auth_provider_id['GITHUB'] |
    auth_provider_id['TWITTER'] |
    auth_provider_id['APPLE'];