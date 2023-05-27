import { Auth, Db, Document, UpdateDescription } from "mongodb";
import express from "express";

interface SimpleError {

}

interface StorageRulesSnapshot {

}

interface DatabaseRulesSnapshot {

}

type LogLevel = 'all' | 'disabled' | 'auth' | 'database' | 'storage' | 'outside-requests' | 'content';

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

interface MosquitoDbServerConfig {
    projectName: string,
    signerKey: string,
    storageRules: (snapshot?: StorageRulesSnapshot) => Promise<void>,
    databaseRules: (snapshot?: DatabaseRulesSnapshot) => Promise<void>,
    port?: number,
    enableSequentialUid?: boolean,
    accessKey: string,
    disableCrossLogin?: boolean,
    logger?: LogLevel | LogLevel[],
    dbUrl?: string,
    dbName?: string,
    mergeAuthAccount?: boolean,
    googleAuthConfig?: GoogleAuthConfig,
    appleAuthConfig?: AppleAuthConfig,
    facebookAuthConfig?: FacebookAuthConfig,
    githubAuthConfig?: GithubAuthConfig,
    twitterAuthConfig?: TwitterAuthConfig,
    fallbackAuthConfig?: FallbackAuthConfig
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
    encryptionKey: string;
    uid: string;
    claims: Object;
    emailVerified: boolean;
    profile: UserProfile;
    disabled: boolean;
}

interface JWTAuthData extends AuthData {
    token: string
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

interface DisconnectTaskInspector {
    status?: 'completed' | 'error' | 'cancelled';
    committed?: boolean;
    simpleError?: SimpleError;
    task?: ({ commands: WriteCommand, dbName?: string, dbUrl?: string })
}

export default class MosquitoDbServer {
    constructor(config: MosquitoDbServerConfig);

    getDatabase(dbName?: string, dbUrl?: string): Db;
    listenHttpsRequest(route: string, callback?: (request: express.Request, response: express.Response, auth?: JWTAuthData | null) => void, options?: MosquitoDbHttpOptions): void;
    listenDatabase(collection: string, callback?: (data: DatabaseListenerCallbackData) => void, options?: DatabaseListenerOption): void;
    listenStorage(collection: string, callback?: () => void): void;
    uploadBuffer(destination: string, buffer: Buffer): Promise<string>;
    deleteFile(path: string): Promise<void>;
    listenNewUser(callback?: (user: NewUserAuthData) => void): void;
    listenDeletedUser(callback?: (uid: string) => void): void;
    inspectDocDisconnectionTask(callback?: (data: DisconnectTaskInspector) => void): void;
    updateUserProfile(uid: string, profile: UserProfile): Promise<void>;
    updateUserClaims(uid: string, claims: Object): Promise<void>;
    updateUserEmailAddress(uid: string, email: string): Promise<void>;
    updateUserPassword(uid: string, password: string): Promise<void>;
    updateUserEmailVerify(uid: string, verified: boolean): Promise<void>;
    disableUser(uid: string, disable: boolean): Promise<void>;
}

export function STORAGE_URL_TO_FILE(url: string, projectName: string): string;