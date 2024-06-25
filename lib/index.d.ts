import { Db, Document, MongoClient, SortDirection, UpdateDescription } from "mongodb";
import express from "express";
import { CorsOptions } from "cors";
import { Sort } from "mongodb";
import { Filter } from "mongodb";
import { UpdateFilter } from "mongodb";
import type { IncomingHttpHeaders } from "http";
import type { ParsedUrlQuery } from "querystring";
import { Socket } from "socket.io";
import { TokenPayload } from "google-auth-library";

interface SimpleError {
    simpleError?: {
        error: string;
        message: string;
    }
}

interface PureHttpRequest extends express.Request {
    res: undefined
}

interface StorageRulesSnapshot {

}

interface BatchUpdateValue {
    scope: 'setOne' | 'setMany' | 'updateOne' | 'mergeOne' | 'deleteOne' | 'deleteMany' | 'replaceOne' | 'putOne';
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
}

interface DatabaseRulesBatchWritePrescription {
    value: BatchUpdateValue[];
}

interface DatabaseRulesSnapshot {
    auth?: JWTAuthData | undefined;
    endpoint: '_readDocument' | '_queryCollection' | '_writeDocument' | '_writeMapDocument' | '_documentCount' | '_listenCollection' | '_listenDocument' | '_startDisconnectWriteTask' | '_cancelDisconnectWriteTask';
    prescription?: DatabaseRulesIOPrescription | DatabaseRulesBatchWritePrescription;
    dbName?: string;
    dbRef?: string;
}

type LogLevel = 'all' | 'auth' | 'database' | 'storage' | 'external-requests' | 'served-content' | 'database-snapshot';

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

interface SneakSignupAuthConfig {
    email?: string;
    password?: string;
    photo?: string;
    name?: string;
    metadata: Object
    token?: string;
    request: express.Request;
    method: 'custom' | 'google' | 'apple' | 'github' | 'twitter' | 'facebook';
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
}

interface TransformMediaOption {
    localBuffer: Buffer;
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
    onSocketSnapshot?: (snapshot?: MSocketSnapshot, error?: MSocketError) => void;
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
     * - `served-content`: log serve content requests
     * - `database-snapshot`: log database snapshot events
     */
    logger?: LogLevel | LogLevel[];
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
     * ```js
     * import MosquitoTransportServer from "mosquito-transport";
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
     *         if (method === 'custom' && password.length < 5)
     *             throw 'password is too short';
     *         const uid = randomString(11),
     *             lang = getCountryLang(geo?.country || 'US');
     *         return {
     *             metadata: {
     *                 country: geo.country,
     *                 city: geo.city,
     *                 location: geo.ll,
     *                 tz: geo?.timezone,
     *                 ip: request.ip,
     *                 locale: 'en'
     *             },
     *             uid
     *         };
     *     }
     * });
     * ```
     */
    sneakSignupAuth?: (config: SneakSignupAuthConfig) => SneakSignupAuthResult;
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
    metadata: Object;
    signupMethod: 'google' | 'apple' | 'custom' | 'twitter' | 'facebook' | 'github' | string;
    joinedOn: number;
    uid: string;
    claims: Object;
    emailVerified: boolean;
    profile: UserProfile;
    disabled: boolean;
}

interface UserData extends AuthData {
    password?: string;
}

interface JWTAuthData extends AuthData {
    token: string;
    exp?: number;
    aud?: string;
    iss?: string;
    sub?: string;
}

interface NewUserAuthData extends AuthData {
    password?: string;
    google_sub?: string;
    apple_sub?: string;
    twitter_sub?: string;
    github_sub?: string;
    facebook_sub?: string;
}

interface MosquitoDbHttpOptions {
    enforceUser?: boolean;
    validateUser?: boolean;
    enforceVerifiedUser?: boolean;
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
    systemDest: string;
    dest: string;
    buffer?: Buffer;
    operation: 'uploadFile' | 'deleteFile' | 'deleteFolder';
    auth?: JWTAuthData;
}

interface RawBodyRequest extends express.Request {
    rawBody: Buffer;
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
    validateToken(token: string, isRefreshToken?: boolean): Promise<AuthData>;

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
    listenHttpsRequest(route: string, callback?: (request: RawBodyRequest, response: express.Response, auth?: JWTAuthData | null) => void, options?: MosquitoDbHttpOptions): void;
    listenDatabase(collection: string, callback?: (data: DatabaseListenerCallbackData) => void, options?: DatabaseListenerOption): void;
    listenStorage(callback?: (snapshot: StorageSnapshot) => void): () => void;
    uploadBuffer(destination: string, buffer: Buffer): Promise<string>;
    deleteFile(path: string): Promise<void>;
    deleteFolder(path: string): Promise<void>;
    listenNewUser(callback?: (user: NewUserAuthData) => void): void;
    listenDeletedUser(callback?: (uid: string) => void): void;
    inspectDocDisconnectionTask(callback?: (data: DisconnectTaskInspector) => void): void;
    updateUserProfile(uid: string, profile: UserProfile): Promise<void>;
    updateUserClaims(uid: string, claims: Object): Promise<void>;
    updateUserEmailAddress(uid: string, email: string): Promise<void>;
    updateUserPassword(uid: string, password: string): Promise<void>;
    updateUserEmailVerify(uid: string, verified: boolean): Promise<void>;
    disableUser(uid: string, disable: boolean): Promise<void>;
    getUserData(uid: string): Promise<UserData>;
    linkToFile(link: string): string;
}