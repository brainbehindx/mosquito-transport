import express from "express";
import { emitDatabase, TIMESTAMP, TIMESTAMP_OFFSET } from "./products/database/index.js";
import { removeVideoFreezer, validateStoragePath } from "./products/storage/index.js";
import { Scoped } from "./helpers/variables.js";
import { decodeBinary, normalizeRoute } from "./helpers/utils.js";
import { getDB } from "./products/database/base.js";
import { releaseTokenSelfDestruction, validateJWT, verifyJWT } from "./products/auth/tokenizer.js";
import { ADMIN_DB, AUTH_PROVIDER_ID, DEFAULT_DB, ERRORS, EnginePath, STORAGE_DIRS, STORAGE_ROUTE } from "./helpers/values.js";
import { SignoutUserSignal, StorageListener, UserCountReadyListener } from "./helpers/listeners.js";
import { rm } from "fs/promises";
import { cleanUserToken, invalidateToken } from "./products/auth/email_auth.js";
import naclPkg from 'tweetnacl-functional';
import { simplifyError } from 'simplify-error';
import { Validator } from "guard-object";
import { cleanupPendingHashes, deleteDir, deleteSource, getSource, readBuffer, streamReadableSource, streamWritableSource, writeBuffer } from "./products/storage/store.js";
import { join } from "path";
import { hash } from "argon2";
import { DoNotEncrypt, mtInit } from "./zb-init.js";
import { validateServerConfig, InternalRoutes } from "./zb-validator.js";
import { onApiRequest } from "./products/http/request.js";
import { MongoClient } from "mongodb";

const { box } = naclPkg;

const PORT = process.env.MOSQUITO_PORT || 4291;
const localMongo = { client: undefined, map: new Map() };

export default class MosquitoTransportServer {
    constructor(configx) {
        const config = {
            ...configx,
            ddosMap: configx.ddosMap || {
                auth: {
                    signup: { calls: 7, perSeconds: 60 * 30 },
                    signin: { calls: 10, perSeconds: 60 * 10 },
                    google_signin: { calls: 10, perSeconds: 60 * 5 },
                    apple_signin: { calls: 10, perSeconds: 60 * 5 }
                }
            },
            logger: (Array.isArray(configx.logger) ? configx.logger : [configx.logger || 'error']).filter(v => v),
            externalAddress: configx.externalAddress || `http://${configx.hostname || 'localhost'}:${configx.port || PORT}`,
            enforceE2E_Encryption: configx.enforceE2E
        };

        this.projectName = config.projectName?.trim?.();

        if (!configx?.mongoInstances) {
            const client =
                localMongo.client ||
                (localMongo.client = new MongoClient('mongodb://localhost:27017'));
            const mref = {};

            config.mongoInstances = {
                [ADMIN_DB]: client.db(`${this.projectName}_${ADMIN_DB}`),
                [DEFAULT_DB]: client.db(`${this.projectName}_${DEFAULT_DB}`)
            };

            localMongo.map.set(mref);

            this.__remove_local_mongo = () => {
                localMongo.map.delete(mref);
                if (!localMongo.map.size && localMongo.client) {
                    localMongo.client.close();
                    delete localMongo.client;
                }
            }
        }

        validateServerConfig(config, this);

        const {
            signerKey,
            storageRules,
            databaseRules,
            port,
            enableSequentialUid,
            logger,
            externalAddress,
            uidLength,
            accessTokenInterval,
            refreshTokenExpiry,
            e2eKeyPair,
            dumpsterPath,
            mongoInstances,
            autoPurgeToken,
            mergeAuthAccount,
            interceptNewAuth,
            googleAuthConfig,
            appleAuthConfig
        } = config;

        this.externalAddress = externalAddress;
        this.port = port || PORT;

        if (Scoped.InstancesData[this.projectName])
            throw `Cannot initialize ${this.constructor.name}() with projectName:"${this.projectName}" multiple times`;

        if (Scoped.expressInstances[this.port])
            throw `Port ${this.port} is currently being used by another ${this.constructor.name}() instance`;

        Scoped.InstancesData[this.projectName] = {
            externalAddress,
            mongoInstances,
            E2E_BufferPair: (e2eKeyPair || []).map(v => new Uint8Array(Buffer.from(v, 'base64'))),
            accessTokenInterval,
            refreshTokenExpiry,
            signerKey,
            uidLength,
            dumpsterPath,
            enableSequentialUid: !!enableSequentialUid,
            databaseRules,
            storageRules,
            mergeAuthAccount,
            interceptNewAuth
        };

        Scoped.expressInstances[this.port] = express();

        getDB(this.projectName, ADMIN_DB)
            .collection(EnginePath.userAcct)
            .estimatedDocumentCount({})
            .then(n => {
                if (!Scoped.InstancesData[this.projectName]) return;

                Scoped.SequentialUid[this.projectName] = n;
                UserCountReadyListener.dispatchPersist(this.projectName);
            });

        this._socket =
            mtInit(Scoped.expressInstances[this.port], {
                ...config,
                projectName: this.projectName,
                port: this.port,
                logger
            });

        this.config = config;
        this._auto_purge_listener = releaseTokenSelfDestruction(this.projectName, autoPurgeToken === undefined || autoPurgeToken);
        this._db_events = new Map();

        rm(STORAGE_DIRS(this.projectName).VID_CACHER, {
            recursive: true,
            force: true
        }).catch(() => null);
        cleanupPendingHashes(this.projectName);

        const providerSubIndexes =
            [
                googleAuthConfig ? { [AUTH_PROVIDER_ID.GOOGLE]: 1 } : null,
                appleAuthConfig ? { [AUTH_PROVIDER_ID.APPLE]: 1 } : null
            ].filter(v => v);

        // create mongodb index
        setTimeout(() => {
            Promise.all([
                [EnginePath.userAcct, [{ email: 1 }, ...providerSubIndexes]],
                [EnginePath.refreshTokenStore, [{ uid: 1 }, { createdOn: -1 }]]
            ].map(([path, indexes]) =>
                Promise.all(
                    indexes.map(d =>
                        this.admin_db.collection(path).createIndex(d)
                    )
                )
            ));
        }, 3);
    };

    get sampleE2E() {
        const keyPair = box.keyPair();
        return [
            keyPair.publicKey,
            keyPair.secretKey
        ].map(v => Buffer.from(v).toString('base64'));
    };

    get storagePath() {
        return STORAGE_DIRS(this.projectName).FILES;
    }

    get express() {
        return Scoped.expressInstances[this.port];
    };

    destroy = () => {
        if (!Scoped.InstancesData[this.projectName]) return;

        this._socket.close();
        this._auto_purge_listener();
        this._db_events.forEach((_, k) => {
            k();
        });
        this._db_events.clear();
        this.__remove_local_mongo();

        delete Scoped.InstancesData[this.projectName];
        delete Scoped.expressInstances[this.port];
        if (Scoped.SequentialUid[this.projectName])
            delete Scoped.SequentialUid[this.projectName];
    }

    signOutUser = async (uid) => {
        await this.admin_db.collection(EnginePath.refreshTokenStore).deleteMany({ uid });
        SignoutUserSignal.dispatch('d', uid);
    };

    verifyToken = (token, isRefreshToken) => verifyJWT(token, this.projectName, isRefreshToken);
    validateToken = (token, isRefreshToken) => validateJWT(token, this.projectName, isRefreshToken);
    invalidateToken = (token, isRefreshToken) => invalidateToken(token, this.projectName, isRefreshToken);

    getDatabase = (dbName, dbUrl) => getDB(this.projectName, dbUrl, dbName);

    get db() {
        return this.getDatabase();
    }

    get admin_db() {
        return this.getDatabase(undefined, ADMIN_DB);
    }

    listenHttpsRequest = (route, callback, options) =>
        onApiRequest(route, callback, options, this);

    listenDatabase = (path, callback, options) => {
        if (typeof path !== 'string') throw `listenDatabase first argument must be a string but got ${path}`;
        const { dbName, dbUrl } = options || {};
        const { logger } = this.config;
        const hasLogger = logger.includes('all') || logger.includes('database-snapshot'),
            hasErrorLogger = logger.includes('all') || logger.includes('error');

        const stop = emitDatabase(path, async function () {
            const now = hasLogger && performance.now();
            if (hasLogger) {
                const { extras, after, ...restSnapshot } = arguments[0];
                console.log(`db-snapshot ${path}: `, restSnapshot);
            }

            try {
                await callback?.(...arguments);
            } catch (e) {
                if (hasErrorLogger) console.error(`db-snapshot Error ${path}: `, e);
            }
            if (hasLogger) console.log(`db-snapshot ${path} took: ${performance.now() - now}ms`);
        }, this.projectName, dbName, dbUrl, options);

        this._db_events.set(stop);

        return () => {
            this._db_events.delete(stop);
            return stop();
        };
    };

    getStorageSource = (path) =>
        getSource(path, this.projectName)
            .then(r => r.source ? r : null);

    createWriteStream = (destination, createHash, callback) => {
        validateStoragePath(destination);
        if (![undefined, true, false].includes(createHash))
            throw 'writeFile() third argument must either be undefined or a boolean value';

        removeVideoFreezer(destination, this.projectName);

        return streamWritableSource(
            destination,
            createHash,
            this.projectName,
            err => {
                if (err) callback?.(err);
                else {
                    const linkAccess = new URL(this.externalAddress);
                    linkAccess.pathname = join(STORAGE_ROUTE, normalizeRoute(destination));
                    callback?.(undefined, linkAccess.href);
                }
            }
        );
    };

    writeFile = async (destination, buffer, createHash) => {
        validateStoragePath(destination);
        if (!Buffer.isBuffer(buffer)) throw 'writeFile() second argument must be a buffer';
        if (![undefined, true, false].includes(createHash))
            throw 'writeFile() third argument must either be undefined or a boolean value';

        removeVideoFreezer(destination, this.projectName);

        await writeBuffer(destination, buffer, this.projectName, createHash);

        const linkAccess = new URL(this.externalAddress);
        linkAccess.pathname = join(STORAGE_ROUTE, normalizeRoute(destination));
        return linkAccess.href;
    };

    readFile = (path) => {
        validateStoragePath(path);
        return readBuffer(path, this.projectName);
    }

    createReadStream = (path) => {
        validateStoragePath(path);
        return streamReadableSource(path, this.projectName);
    }

    deleteFile = async (path = '') => {
        if (Validator.LINK(path)) {
            const url = new URL(path);
            if (!url.pathname.startsWith(`${STORAGE_ROUTE}/`))
                throw `link must have a pathname that starts with ${STORAGE_ROUTE}/`;
            path = url.pathname.substring(STORAGE_ROUTE.length);
        }
        validateStoragePath(path);
        removeVideoFreezer(path, this.projectName);
        await deleteSource(path, this.projectName);
    };

    deleteFolder = async (path = '') => {
        validateStoragePath(path);

        removeVideoFreezer(path, this.projectName, true);
        await deleteDir(path, this.projectName);
    };

    listenStorage = (callback) => {
        const { logger } = this.config;
        const hasLogger = logger.includes('all') || logger.includes('storage'),
            hasErrorLogger = logger.includes('all') || logger.includes('error');

        return StorageListener.listenTo(this.projectName, async ({ dest, ...rest }) => {
            const now = hasLogger && performance.now();

            if (hasLogger) console.log(`started listenStorage ${dest}:`);
            try {
                await callback?.({ dest, ...rest });
            } catch (e) {
                if (hasErrorLogger) console.error(`listenStorage Error ${dest}: `, e);
            }
            if (hasLogger) console.log(`listenStorage ${dest} took: ${performance.now() - now}ms`);
        });
    };

    listenNewUser = (callback) =>
        emitDatabase(EnginePath.userAcct, s => {
            if (s.insertion) {
                const j = { ...s.insertion };
                j.uid = j._id;
                if (j._id) delete j._id;
                callback?.(j);
            }
        }, this.projectName, undefined, ADMIN_DB);

    listenDeletedUser = (callback) =>
        emitDatabase(EnginePath.userAcct, s => {
            if (s.deletion) callback?.(s.deletion);
        }, this.projectName, undefined, ADMIN_DB);

    updateUserProfile = async (uid, profile) => {
        if (!Validator.OBJECT(profile)) throw 'updateUserProfile() second argument must be an object';
        if (typeof uid !== 'string' || !uid.trim()) throw 'updateUserProfile() first argument must be a string';

        const validNode = ['email', 'name', 'phoneNumber', 'photo', 'bio'];
        const updateSet = {};
        const updateUnset = {};

        Object.entries(profile).forEach(([k, v]) => {
            if (!validNode.includes(k)) throw `invalid property '${k}', expected any of ${validNode}`;
            if (typeof v !== 'string' && v !== undefined) throw `'${k}' required a string or undefined value but got ${v}`;
            if (v === undefined) {
                updateUnset[`profile.${k}`] = true;
            } else updateSet[`profile.${k}`] = v;
        });

        if (Object.keys(updateSet).length || Object.keys(updateUnset).length)
            await this.getDatabase(undefined, ADMIN_DB)
                .collection(EnginePath.userAcct)
                .updateOne({ _id: uid }, {
                    $set: updateSet,
                    $unset: updateUnset
                });
    };

    updateUserMetadata = async (uid, metadata) => {
        if (!Validator.OBJECT(metadata)) throw 'metadata requires a raw object value';
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';

        const updateSet =
            Object.entries(metadata).map(([k, v]) =>
                v !== undefined && [`metadata.${k}`, v]
            ).filter(v => v);

        const updateUnset =
            Object.entries(metadata).map(([k, v]) =>
                v === undefined && [`metadata.${k}`, true]
            ).filter(v => v);

        if (updateSet.length || updateUnset.length)
            await this.getDatabase(undefined, ADMIN_DB)
                .collection(EnginePath.userAcct)
                .updateOne({ _id: uid }, {
                    ...updateSet.length ? { $set: Object.fromEntries(updateSet) } : {},
                    ...updateUnset.length ? { $unset: Object.fromEntries(updateUnset) } : {}
                });
    };

    updateUserClaims = async (uid, claims) => {
        if (!Validator.OBJECT(claims)) throw 'claims should be an object';
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';

        const updateSet =
            Object.entries(claims).map(([k, v]) =>
                v !== undefined && [`claims.${k}`, v]
            ).filter(v => v);

        const updateUnset =
            Object.entries(claims).map(([k, v]) =>
                v === undefined && [`claims.${k}`, true]
            ).filter(v => v);

        if (updateSet.length || updateUnset.length)
            await this.getDatabase(undefined, ADMIN_DB)
                .collection(EnginePath.userAcct)
                .updateOne({ _id: uid }, {
                    ...updateSet.length ? { $set: Object.fromEntries(updateSet) } : {},
                    ...updateUnset.length ? { $unset: Object.fromEntries(updateUnset) } : {}
                });
    };

    updateUserEmailAddress = async (uid, email) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof email !== 'string' || !email.trim()) throw 'email requires a string value';

        await this.getDatabase(undefined, ADMIN_DB)
            .collection(EnginePath.userAcct)
            .updateOne({ _id: uid }, {
                $set: { email, 'profile.email': email },
                $unset: {
                    [AUTH_PROVIDER_ID.GOOGLE]: true,
                    [AUTH_PROVIDER_ID.APPLE]: true
                }
            });
        await cleanUserToken(uid, this.projectName);
    };

    updateUserPassword = async (uid, password) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof password !== 'string' || !password.trim()) throw ERRORS.PASSWORD_REQUIRED.simpleError.message;

        password = await hash(password);

        await this.getDatabase(undefined, ADMIN_DB)
            .collection(EnginePath.userAcct)
            .updateOne({ _id: uid }, {
                $set: { password }
            });
        await cleanUserToken(uid, this.projectName);
    };

    updateUserPasswordVerified = async (uid, verified) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof verified !== 'boolean') throw 'updateUserPasswordVerified() second argument must be a boolean';

        await this.getDatabase(undefined, ADMIN_DB)
            .collection(EnginePath.userAcct)
            .updateOne({ _id: uid }, {
                $set: { passwordVerified: verified }
            });
    };

    disableUser = async (uid, disabled) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof disabled !== 'boolean') throw 'disabled requires a boolean value';

        await this.getDatabase(undefined, ADMIN_DB)
            .collection(EnginePath.userAcct)
            .updateOne({ _id: uid }, {
                $set: { disabled }
            });
    };

    getUserData = async (uid) => {
        const r =
            await this.getDatabase(undefined, ADMIN_DB)
                .collection(EnginePath.userAcct)
                .findOne({ _id: uid });

        if (!r) throw simplifyError('user_not_found', 'This user was not found on our database record').simpleError;
        return { ...r, uid };
    };
}

export const GEO_JSON = (lat, lng) => ({
    type: "Point",
    coordinates: [lng, lat],
});

export const FIND_GEO_JSON = (location, offSetMeters, centerMeters) => ({
    $nearSphere: {
        $geometry: {
            type: "Point",
            coordinates: location.slice(0).reverse()
        },
        $minDistance: centerMeters || 0,
        $maxDistance: offSetMeters
    }
});

export {
    DoNotEncrypt,
    AUTH_PROVIDER_ID,
    InternalRoutes,
    TIMESTAMP_OFFSET,
    TIMESTAMP
};

export const parseToken = (token) => JSON.parse(decodeBinary(token.split('.')[1]));