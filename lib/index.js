import express from "express";
import compression from "compression";
import { databaseLiveRoutes, databaseRoutes, emitDatabase, writeDocument } from "./products/database/index.js";
import { authLiveRoutes, authRoutes } from "./products/auth/index.js";
import { storageRoutes } from "./products/storage/index.js";
import { Scoped } from "./helpers/variables.js";
import { IS_RAW_OBJECT, niceTry, simplifyError } from "./helpers/utils.js";
import { getDB } from "./products/database/base.js";
import { validateJWT } from "./products/auth/tokenizer.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, EngineRoutes, STORAGE_PATH, STORAGE_ROUTE, STORAGE_URL_TO_FILE } from "./helpers/values.js";
import { validateGoogleAuthConfig } from "./products/auth/googleAuth.js";
import { validateAppleAuthConfig } from "./products/auth/appleAuth.js";
import { validateFacebookAuthConfig } from "./products/auth/facebookAuth.js";
import { validateGithubAuthConfig } from "./products/auth/githubAuth.js";
import { validateTwitterAuthConfig } from "./products/auth/twitterAuth.js";
import { validateFallbackAuthConfig } from "./products/auth/fallbackAuth.js";
import { DisconnectionWriteTaskListener, StorageListener, UserCountReadyListener } from "./helpers/listeners.js";
import GlobalListener from "./helpers/GlobalListener.js";
import EnginePath from "./helpers/EnginePath.js";
import { Server } from "socket.io";
import http from 'http';
import { writeFile } from "fs";
import { mkdirp } from "mkdirp";
import fetch from "node-fetch";
import { unlink } from "fs/promises";

const PORT = process.env.MOSQUITO_PORT || 4291;

const authorizeRequest = (accessKey) => (req, res, next) => {
    const incomingAccessKey = atob(req.headers.authorization?.split('Bearer ')?.join('') || ''),
        authToken = req.headers['mosquitodb-token'];

    if (authToken) req.headers.mtoken = authToken;

    if (incomingAccessKey !== accessKey) {
        res.status(403).send({ status: 'error', ...simplifyError('incorrect_access_key', 'The accessKey been provided is not correct') });
    } else next();
}

const serveStorage = ({ projectName }) => async (req, res, next) => {
    const route = req.url;

    if (typeof route === 'string' && route.startsWith(`${STORAGE_ROUTE}/`)) {
        const { 'mosquitodb-token': authToken } = req.headers,
            auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : null,
            cleanRoute = route.substring(`${STORAGE_ROUTE}/`.length);

        const rulesObj = {
            ...(auth ? { auth: { ...auth, token: authToken } } : {}),
            operation: 'serverFile',
            route: cleanRoute
        };

        try {
            await Scoped.StorageRules[projectName]?.(rulesObj);
        } catch (e) {
            res.status(403).send({ status: 'error', ...simplifyError('security_error', `${e}`) });
            return;
        }

        res.sendFile(`${STORAGE_PATH(projectName)}/${cleanRoute}`, {}, (err) => {
            // console.log('serveStorage: ', err);
            // if (err) {
            //     // res.status(404).send({ status: 'error', ...simplifyError('unexpected_error', `${err}`) });
            // } else
            //  res.status().end();
        });
    } else next();
}

const areYouOk = (req, res, next) => {
    if (req.url === `/${EngineRoutes._areYouOk}`) {
        res.status(200).send({ status: 'yes' });
        return;
    }
    next();
}

const useMosquitoDbServer = (app, config) => {
    const { projectName, port, accessKey, logger } = config;

    app.disable("x-powered-by");
    if (!logger)
        app.use((req, res, next) => {
            console.log('started route:', req.url);
            next();
        });

    [
        compression(),
        areYouOk,
        serveStorage({ projectName }),
        // app.use(STORAGE_ROUTE, express.static(STORAGE_PATH(projectName, ''))),
        express.urlencoded({ type: 'multipart/*', limit: 96751471, extended: false }),
        express.json({ type: '*/json', limit: '20gb' }),
        authorizeRequest(accessKey),
        ...authRoutes({ ...config }),
        ...databaseRoutes({ projectName }),
        ...storageRoutes({ projectName })
    ].forEach(e => {
        app.use(e);
    });

    if (!logger)
        app.use((req, _, next) => {
            console.log('finished route:', req.url);
            next();
        });

    const server = http.createServer(app),
        io = new Server(server);

    io.on('connection', socket => {
        const scope = {};
        authLiveRoutes({ projectName, accessKey }).map(e => e(socket, scope));
        databaseLiveRoutes({ projectName, accessKey }).map(e => e(socket, scope));
    });

    server.listen(port, () => {
        console.log(`mosquitodb server listening on port ${PORT}`);
    });
}


export default class MosquitoDbServer {
    constructor(config) {
        validateServerConfig(config);
        const {
            signerKey,
            storageRules,
            databaseRules,
            port,
            enableSequentialUid,
            disableCrossLogin,
            accessKey,
            logger,
            dbUrl,
            dbName,
            externalAddress
        } = config;

        this.externalAddress = externalAddress;
        this.projectName = config.projectName.trim();
        this.port = port || PORT;

        if (Scoped.serverInstances[this.projectName])
            throw `Cannot initialize MosquitoDbServer() with projectName:"${this.projectName}" multiple times`;

        if (Scoped.expressInstances[`${this.port}`])
            throw `Port ${this.port} is currently being used by another MosquitoDbServer() instance`;

        Scoped.expressInstances[`${this.port}`] = express();
        Scoped.DatabaseUrl[this.projectName] = dbUrl;
        Scoped.DatabaseName[this.projectName] = dbName;

        getDB(this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL).collection(EnginePath.userAcct()).countDocuments({}).then(n => {
            Scoped.SequentialUid[this.projectName] = n;
            UserCountReadyListener.triggerKeyListener(this.projectName);
        });

        useMosquitoDbServer(Scoped.expressInstances[`${this.port}`], {
            ...config,
            projectName: this.projectName,
            port: this.port,
            accessKey,
            logger
        });

        StorageListener[this.projectName] = new GlobalListener();
        Scoped.DatabaseRules[this.projectName] = databaseRules;
        Scoped.StorageRules[this.projectName] = storageRules;
        Scoped.AuthHashToken[this.projectName] = signerKey;
        Scoped.EnableSequentialUid[this.projectName] = !!enableSequentialUid;
        Scoped.DisableCrossLogin[this.projectName] = !!disableCrossLogin;
    }

    getDatabase = (dbName, dbUrl) => {
        if (dbName === ADMIN_DB_NAME) throw `getDatabase() first argument cannot be ${ADMIN_DB_NAME}`;
        return getDB(this.projectName, dbName, dbUrl);
    };

    listenHttpsRequest(route = '', callback, options) {
        Scoped.expressInstances[`${this.port}`].use(express.Router({ caseSensitive: true }).all(`${this.projectName}${route.startsWith('/') ? '' : '/'}${route}`, async (req, res) => {
            const { 'mosquitodb-token': authToken } = req.headers,
                enforceUser = options?.enforceVerifiedUser || options?.enforceUser;

            let auth;

            try {
                if (authToken && (enforceUser || options?.validateUser)) {
                    auth = await validateJWT(authToken, this.projectName);
                } else if (enforceUser) throw simplifyError('unauthorize_access', 'Only authorized users can access this request');

                if (options?.enforceVerifiedUser && !auth.emailVerified)
                    throw simplifyError('unverified_email', 'User email is not verified, Please verify and try again');
            } catch (e) {
                if (enforceUser) {
                    res.status(403).send({ status: 'error', ...e });
                    return;
                }
            }

            callback(req, res, auth ? { ...auth, token: authToken } : null);
        }));
    }

    listenDatabase(path, callback, options) {
        const { dbName, dbUrl } = options;
        if (dbName === ADMIN_DB_NAME) throw `listenDatabase() dbName can have any string value but not '${ADMIN_DB_NAME}'`;
        if (dbUrl === ADMIN_DB_NAME) throw `listenDatabase() dbUrl can have any string value but not '${ADMIN_DB_URL}'`;

        return emitDatabase(path, callback, this.projectName, dbName, dbUrl, options);
    }

    uploadBuffer = (destination, buffer) => new Promise(async (resolve, reject) => {
        try {
            if (typeof destination !== 'string' || !destination.trim())
                throw 'uploadBuffer() first argument must be a string';

            if (!Buffer.isBuffer(buffer)) throw 'uploadBuffer() second argument must be a buffer';

            const to = destination.trim(),
                directory = `${STORAGE_PATH(this.projectName)}/${to}`,
                tipDir = directory.split('/').filter((_, i, a) => i !== a.length - 1).join('/'),
                downloadUrl = `${this.externalAddress}${STORAGE_ROUTE}/${to}`,
                destErr = validateDestination(destination);

            if (destErr) throw simplifyError('invalid_destination', destErr);
            await mkdirp(tipDir);

            writeFile(directory, buffer, (err) => {
                if (err) {
                    reject(simplifyError('unexpected_error', `${err.message}`));
                } else resolve(downloadUrl);
            });
        } catch (e) {
            reject(e.simpleError ? e : simplifyError('unexpected_error', `${e}`));
        }
    })

    deleteFile = async (path) => {
        await unlink(`${STORAGE_PATH(this.projectName)}/${path}`);
    }

    // TODO:
    listenStorage(path, callback) {
        if (typeof path !== 'string') throw `path is invalid in listenStorage(), expected a string value but got ${typeof path}`;
        return StorageListener[this.projectName].startKeyListener(path, callback);
    }

    listenNewUser = (callback) => emitDatabase(EnginePath.userAcct(), s => {
        if (s.insertion) {
            const j = { ...s.insertion };
            j.uid = j._id;
            if (j._id) delete j._id;
            callback?.(j);
        }
    }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

    listenDeletedUser = (callback) => emitDatabase(EnginePath.userAcct(), s => {
        if (s.deletion) callback?.(s.deletion);
    }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

    inspectDocDisconnectionTask = (callback) => DisconnectionWriteTaskListener[this.projectName].startListener(callback);

    async updateUserProfile(uid, profile) {
        if (!IS_RAW_OBJECT(profile)) throw `profile requires a raw object value`;

        const validNode = ['email', 'name', 'phoneNumber', 'photo', 'bio'],
            update = {};

        Object.keys(profile).forEach(e => {
            if (!validNode.includes(e)) throw `invalid property '${e}', expected any of ${validNode}`;
            if (typeof validNode[e] !== 'string') throw `'${e}' required a string value but got ${e}`;
            update[`profile.${e}`] = profile[e];
        });

        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;

        if (Object.keys(update).length)
            await writeDocument({ scope: 'updateOne', find: { _id: uid }, path: EnginePath.userAcct(), value: { $set: update } });
    }

    async updateUserClaims(uid, claims) {
        if (!IS_RAW_OBJECT(claims)) throw `profile requires a raw object value`;

        const update = {};

        Object.keys(claims).forEach(e => {
            update[`claims.${e}`] = claims[e];
        });

        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;

        if (Object.keys(update).length)
            await writeDocument({ scope: 'updateOne', find: { _id: uid }, path: EnginePath.userAcct(), value: { $set: update } });
    }

    async updateUserEmailAddress(uid, email) {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof email !== 'string' || !email.trim()) throw `email requires a string value`;

        await writeDocument({ scope: 'updateOne', find: { _id: uid }, path: EnginePath.userAcct(), value: { $set: { email, 'profile.email': email } } });
    }

    async updateUserPassword(uid, password) {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof password !== 'string' || !password.trim()) throw `email requires a string value`;

        await writeDocument({ scope: 'updateOne', find: { _id: uid }, path: EnginePath.userAcct(), value: { $set: { password } } });
    }

    async updateUserEmailVerify(uid, verified) {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof verified !== 'boolean') throw `updateUserEmailVerify() second argument must be a boolean`;

        await writeDocument({ scope: 'updateOne', find: { _id: uid }, path: EnginePath.userAcct(), value: { $set: { emailVerified: verified } } });
    }

    async disableUser(uid, disable) {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof disable !== 'boolean') throw `disable requires a string value`;

        await writeDocument({ scope: 'updateOne', find: { _id: uid }, path: EnginePath.userAcct(), value: { $set: { disable } } });
    }

    extractBackup() { }
}

const projectNameWrongChar = ['/', '\\', '.', '$', '%', '#', '!', '*', '?'];
const loggerOptions = ['all', 'disabled', 'auth', 'database', 'storage', 'outside-requests', 'content']

const validateServerConfig = (config) => {
    if (!IS_RAW_OBJECT(config))
        throw 'Expected a raw object in MosquitoDbServer() constructor';

    const {
        projectName,
        signerKey,
        storageRules,
        databaseRules,
        port,
        enableSequentialUid,
        accessKey,
        disableCrossLogin,
        logger,
        dbUrl,
        dbName,
        mergeAuthAccount,
        googleAuthConfig,
        appleAuthConfig,
        facebookAuthConfig,
        githubAuthConfig,
        twitterAuthConfig,
        fallbackAuthConfig
    } = config;

    if (!projectName?.trim() || typeof projectName.trim() !== 'string')
        throw '"projectName" is required in MosquitoDbServer() constructor';

    if (!accessKey?.trim() || typeof accessKey.trim() !== 'string')
        throw '"accessKey" is required in MosquitoDbServer() constructor';

    if (projectNameWrongChar.filter(v => projectName.includes(v)).length)
        throw `projectName must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (projectNameWrongChar.filter(v => `${port || ''}`.includes(v)).length)
        throw `port must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (databaseRules && typeof databaseRules !== 'function')
        throw `databaseRules type must be function but got ${typeof databaseRules}`;

    if (storageRules && typeof storageRules !== 'function')
        throw `storageRules type must be function but got ${typeof storageRules}`;

    if ((signerKey?.trim() || '').length !== 90 || typeof signerKey?.trim() !== 'string')
        throw `signerKey must have string length equals to 90 trimmed characters`;

    if (enableSequentialUid !== undefined && typeof enableSequentialUid !== 'boolean')
        throw `invalid value supplied to enableSequentialUid, expected a boolean but got ${typeof enableSequentialUid}`;

    if (disableCrossLogin !== undefined && typeof disableCrossLogin !== 'boolean')
        throw `invalid value supplied to disableCrossLogin, expected a boolean but got ${typeof disableCrossLogin}`;

    if (mergeAuthAccount !== undefined && typeof mergeAuthAccount !== 'boolean')
        throw `invalid value supplied to mergeAuthAccount, expected a boolean but got ${typeof disableCrossLogin}`;

    if (logger && (Array.isArray(logger) ? logger : [logger]).filter(v => !loggerOptions.includes(v)).length)
        throw `invalid value supplied to logger, expected any of ${loggerOptions.join(', ')}`;

    if (dbUrl && typeof dbUrl !== 'string') throw `dbUrl must be a string`;
    if (dbName && typeof dbName !== 'string') throw `dbName must be a string`;

    if (googleAuthConfig) validateGoogleAuthConfig(googleAuthConfig);
    if (appleAuthConfig) validateAppleAuthConfig(googleAuthConfig);
    if (facebookAuthConfig) validateFacebookAuthConfig(googleAuthConfig);
    if (githubAuthConfig) validateGithubAuthConfig(googleAuthConfig);
    if (twitterAuthConfig) validateTwitterAuthConfig(googleAuthConfig);
    if (fallbackAuthConfig) validateFallbackAuthConfig(googleAuthConfig);
}

const validateDestination = (t = '') => {
    t = t.trim();

    if (!t || typeof t !== 'string') return `destination is required`;
    if (t.startsWith('/') || t.endsWith('/')) return 'destination must neither start with "/" nor end with "/"';
    let l = '', r;

    t.split('').forEach(e => {
        if (e === '/' && l === '/') r = 'invalid destination path, "/" cannot be side by side';
        l = e;
    });

    return r;
};

export {
    STORAGE_URL_TO_FILE
}