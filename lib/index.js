import express from "express";
import compression from "compression";
import { databaseLiveRoutes, databaseRoutes, emitDatabase, readDocument, writeDocument } from "./products/database/index.js";
import { authLiveRoutes, authRoutes } from "./products/auth/index.js";
import { storageRoutes } from "./products/storage/index.js";
import { Scoped } from "./helpers/variables.js";
import { IS_RAW_OBJECT, IS_WHOLE_NUMBER, decryptString, encryptString, niceTry, simplifyCaughtError, simplifyError } from "./helpers/utils.js";
import { getDB } from "./products/database/base.js";
import { validateJWT, verifyJWT } from "./products/auth/tokenizer.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, EngineRoutes, STORAGE_PATH, STORAGE_ROUTE, STORAGE_URL_TO_FILE, one_mb } from "./helpers/values.js";
import { validateGoogleAuthConfig } from "./products/auth/googleAuth.js";
import { validateAppleAuthConfig } from "./products/auth/appleAuth.js";
import { validateFacebookAuthConfig } from "./products/auth/facebookAuth.js";
import { validateGithubAuthConfig } from "./products/auth/githubAuth.js";
import { validateTwitterAuthConfig } from "./products/auth/twitterAuth.js";
import { validateFallbackAuthConfig } from "./products/auth/fallbackAuth.js";
import { DisconnectionWriteTaskListener, StorageListener, UserCountReadyListener } from "./helpers/listeners.js";
import EnginePath from "./helpers/EnginePath.js";
import { Server } from "socket.io";
import http from 'http';
import { mkdirp } from "mkdirp";
import { unlink, writeFile } from "fs/promises";
import { cleanUserToken } from "./products/auth/customAuth.js";
import { invalidateToken } from "./products/auth/customAuth.js";
import cors from 'cors';

const PORT = process.env.MOSQUITO_PORT || 4291;

const serveStorage = ({ projectName, logger, staticContentCacheControl, staticContentMaxAge, staticContentProps }) => async (req, res, next) => {
    const route = req.url;

    if (typeof route === 'string' && route.startsWith(`${STORAGE_ROUTE}/`)) {
        const now = Date.now(),
            hasLogger = logger.includes('all') || logger.includes('served-content');

        if (hasLogger) console.log('started route: ', route);

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

        res.sendFile(`${STORAGE_PATH(projectName)}/${cleanRoute}`, {
            ...staticContentProps,
            maxAge: staticContentMaxAge,
            cacheControl: staticContentCacheControl
        }, (err) => {
            // console.log('serveStorage: ', err);
            // if (err) {
            //     // res.status(404).send({ status: 'error', ...simplifyError('unexpected_error', `${err}`) });
            // } else
            //  res.status().end();
            if (err && hasLogger) console.log(`${route} err: ${err}`);
            if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
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
    const { projectName, port, accessKey, logger, staticContentCacheControl, staticContentMaxAge, staticContentProps, externalAddress, corsOrigin, maxRequestBufferSize, maxUploadBufferSize } = config;

    app.disable("x-powered-by");

    const reqBufferLimiter = [
        express.json({ type: '*/json', limit: maxRequestBufferSize || '100MB' }),
        express.text({ type: 'text/plain', limit: maxRequestBufferSize || '100MB' })
    ];

    [
        ...(corsOrigin === undefined ? [] : [cors({ origin: corsOrigin })]),
        compression(),
        areYouOk,
        serveStorage({ projectName, logger, staticContentCacheControl, staticContentMaxAge, staticContentProps }),
        ...reqBufferLimiter,
        (req, _, next) => {
            const authToken = req.headers['mosquitodb-token'];
            if (authToken) req.headers.mtoken = authToken;
            next();
        },
        ...authRoutes({ ...config }),
        ...databaseRoutes({ projectName, logger, accessKey }),
        express.text({ type: 'text/plain', limit: maxUploadBufferSize || '10GB' }),
        express.raw({ type: 'buffer/upload', limit: maxUploadBufferSize || '10GB' }),
        ...storageRoutes({ projectName, logger, externalAddress, accessKey }),
        ...reqBufferLimiter
    ].forEach(e => {
        app.use(e);
    });

    const server = http.createServer(app),
        io = new Server(server, {
            pingTimeout: 3000,
            pingInterval: 1500,
            ...(corsOrigin === undefined ? undefined : { cors: { origin: corsOrigin } }),
            maxHttpBufferSize: maxRequestBufferSize || (one_mb * 100)
        });

    io.on('connection', socket => {
        const scope = {};
        authLiveRoutes({ projectName, accessKey, logger }).map(e => e(socket, scope));
        databaseLiveRoutes({ projectName, accessKey, logger }).map(e => e(socket, scope));
    });

    server.listen(port, () => {
        console.log(`mosquitodb server listening on port ${port}`);
    });
}


export default class MosquitoDbServer {
    constructor(configx) {
        const config = {
            ...configx,
            logger: (Array.isArray(configx.logger) ? configx.logger : [configx.logger]).filter(v => v),
            externalAddress: configx.externalAddress || `http://${configx.hostname || 'localhost'}:${configx.port || PORT}`
        };

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

        getDB(this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL).collection(EnginePath.userAcct).countDocuments({}).then(n => {
            Scoped.SequentialUid[this.projectName] = n;
            UserCountReadyListener.dispatch(this.projectName);
        });

        useMosquitoDbServer(Scoped.expressInstances[`${this.port}`], {
            ...config,
            projectName: this.projectName,
            port: this.port,
            accessKey,
            logger
        });

        Scoped.DatabaseRules[this.projectName] = databaseRules;
        Scoped.StorageRules[this.projectName] = storageRules;
        Scoped.AuthHashToken[this.projectName] = signerKey;
        Scoped.EnableSequentialUid[this.projectName] = !!enableSequentialUid;
        Scoped.DisableCrossLogin[this.projectName] = !!disableCrossLogin;
        this.config = config;
    }

    verifyToken = async (token) => {
        const r = await verifyJWT(token, this.projectName),
            baseToken = await readDocument({ path: EnginePath.tokenStore, find: { _id: r.tokenID } }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

        if (!baseToken) throw 'Token was either deleted or doesn\'t exists';
        return r;
    }

    checkToken = (token) => verifyJWT(token, this.projectName);

    validateToken = (token) => validateJWT(token, this.projectName);
    invalidateToken = (token) => invalidateToken(token, this.projectName);

    linkToFile = (link) => STORAGE_URL_TO_FILE(link, this.projectName);

    getDatabase = (dbName, dbUrl) => {
        if (dbName === ADMIN_DB_NAME) throw `getDatabase() first argument cannot be ${ADMIN_DB_NAME}`;
        return getDB(this.projectName, dbName, dbUrl);
    };

    listenHttpsRequest = (route = '', callback, options) => {
        Scoped.expressInstances[`${this.port}`].use(express.Router({ caseSensitive: true }).all(`/${this.projectName}${route.startsWith('/') ? '' : '/'}${route}`, async (req, res) => {
            const { 'mtoken': authToken, authorization, uglified } = req.headers;
            const enforceUser = options?.enforceVerifiedUser || options?.enforceUser,
                { logger, accessKey } = this.config,
                hasLogger = logger.includes('all') || logger.includes('external-requests'),
                now = Date.now();

            if (hasLogger) console.log(`started route: /${req.url}`);

            let auth, hasPassedAuth, nauth;

            try {
                if (authToken && (enforceUser || options?.validateUser)) {
                    auth = await validateJWT(authToken, this.projectName);
                } else if (enforceUser) throw simplifyError('unauthorize_access', 'Only authorized users can access this request');

                if (options?.enforceVerifiedUser && !auth.emailVerified)
                    throw simplifyError('unverified_email', 'User email is not verified, Please verify and try again');

                hasPassedAuth = true;

                if (decryptString((authorization || '').split(' ')[1] || '', accessKey, '_') !== accessKey)
                    throw simplifyError('incorrect_access_key', 'The accessKey provided is not correct');

                if (uglified) {
                    nauth = authToken ? (auth || await niceTry(() => verifyJWT(authToken, this.projectName))) : null;

                    if (authToken && !nauth)
                        throw simplifyError('invalid_auth_token', 'token provided is invalid, unable to decrypt request');
                    const reqBody = decryptString(req.body.__, accessKey, authToken ? nauth?.encryptionKey : accessKey);
                    if (typeof reqBody === 'string') {
                        try {
                            req.body = req.headers["content-type"] === 'application/json' ? JSON.parse(reqBody) : reqBody;
                        } catch (e) { req.body = undefined; }
                    } else throw simplifyError('decryption_failed', 'Decrypting request body failed');
                }
            } catch (e) {
                if (hasPassedAuth) console.error(`${route} error:`, e);

                if (enforceUser || hasPassedAuth) {
                    res.status(403).appendHeader(
                        'simple_error',
                        JSON.stringify(simplifyCaughtError(e).simpleError || {})
                    ).send({ status: 'error' });
                    return;
                }
            }

            try {
                const sendResult = (s, obj) => {
                    return s.send((uglified && obj && typeof obj === 'object') ?
                        { __: encryptString(JSON.stringify(obj), accessKey, nauth ? nauth.encryptionKey : accessKey) } : obj
                    );
                }

                await callback(req, {
                    ...res,
                    send: (obj) => sendResult(res, obj),
                    status: (status) => {
                        const s = res.status(status);

                        return {
                            ...s,
                            send: (obj) => sendResult(s, obj)
                        }
                    }
                }, auth ? { ...auth, token: authToken } : null);
            } catch (e) {
                console.error(`${route} routeErr: `, e);
                if (!res.headersSent) res.end();
            }
            if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
        }));
    }

    listenDatabase = (path, callback, options) => {
        const { dbName, dbUrl } = options || {},
            { logger } = this.config;
        if (dbName === ADMIN_DB_NAME) throw `listenDatabase() dbName can have any string value except '${ADMIN_DB_NAME}'`;
        if (dbUrl === ADMIN_DB_NAME) throw `listenDatabase() dbUrl can have any string value except '${ADMIN_DB_URL}'`;

        return emitDatabase(path, async function () {
            const hasLogger = logger.includes('all') || logger.includes('database-snapshot'),
                now = Date.now();
            if (hasLogger) console.log(`db-snapshot ${path}: `, arguments[0]);
            try {
                await callback?.(...arguments);
            } catch (e) {
                console.error(`db-snapshot Error ${path}: `, e);
            }
            if (hasLogger) console.log(`db-snapshot ${path} took: ${Date.now() - now}ms`);
        }, this.projectName, dbName, dbUrl, options);
    }

    uploadBuffer = async (destination, buffer) => {
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

            await writeFile(directory, buffer);
            return downloadUrl;
        } catch (e) {
            throw simplifyCaughtError(e).simpleError;
        }
    }

    deleteFile = async (path = '') => {
        if (path.startsWith('http://') || path.startsWith('https://'))
            path = path.split('/storage/').filter((_, i) => i).join('/storage/');

        await unlink(`${STORAGE_PATH(this.projectName)}/${path}`);
    }

    listenStorage = (callback) => {
        const { logger } = this.config;

        return StorageListener.listenTo(this.projectName, async ({ dest, ...rest }) => {
            const hasLogger = logger.includes('all') || logger.includes('storage'),
                now = Date.now();

            if (hasLogger) console.log(`started listenStorage ${dest}:`);
            try {
                await callback?.({ dest, ...rest });
            } catch (e) {
                console.error(`listenStorage Error ${dest}: `, e);
            }
            if (hasLogger) console.log(`listenStorage ${dest} took: ${Date.now() - now}ms`);
        });
    }

    listenNewUser = (callback) => emitDatabase(EnginePath.userAcct, s => {
        if (s.insertion) {
            const j = { ...s.insertion };
            j.uid = j._id;
            if (j._id) delete j._id;
            callback?.(j);
        }
    }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

    listenDeletedUser = (callback) => emitDatabase(EnginePath.userAcct, s => {
        if (s.deletion) callback?.(s.deletion);
    }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

    inspectDocDisconnectionTask = (callback) => DisconnectionWriteTaskListener.listenTo(this.projectName, callback);

    updateUserProfile = async (uid, profile) => {
        if (!IS_RAW_OBJECT(profile)) throw `profile requires a raw object value`;

        const validNode = ['email', 'name', 'phoneNumber', 'photo', 'bio'],
            update = {};

        Object.keys(profile).forEach(e => {
            if (!validNode.includes(e)) throw `invalid property '${e}', expected any of ${validNode}`;
            if (typeof profile[e] !== 'string') throw `'${e}' required a string value but got ${profile[e]}`;
            update[`profile.${e}`] = profile[e];
        });

        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;

        if (Object.keys(update).length)
            await writeDocument({
                scope: 'updateOne',
                find: { _id: uid },
                path: EnginePath.userAcct,
                value: { $set: update }
            }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    }

    updateUserClaims = async (uid, claims) => {
        if (!IS_RAW_OBJECT(claims)) throw `profile requires a raw object value`;

        const update = {};

        Object.keys(claims).forEach(e => {
            update[`claims.${e}`] = claims[e];
        });

        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;

        if (Object.keys(update).length)
            await writeDocument({
                scope: 'updateOne',
                find: { _id: uid },
                path: EnginePath.userAcct,
                value: { $set: update }
            }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    }

    updateUserEmailAddress = async (uid, email) => {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof email !== 'string' || !email.trim()) throw `email requires a string value`;

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { email, 'profile.email': email } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        await cleanUserToken(uid, this.projectName);
    }

    updateUserPassword = async (uid, password) => {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof password !== 'string' || !password.trim()) throw `email requires a string value`;

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { password } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        await cleanUserToken(uid, this.projectName);
    }

    updateUserEmailVerify = async (uid, verified) => {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof verified !== 'boolean') throw `updateUserEmailVerify() second argument must be a boolean`;

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { emailVerified: verified } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    }

    disableUser = async (uid, disable) => {
        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;
        if (typeof disable !== 'boolean') throw `disable requires a string value`;

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { disable } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    }

    getUserData = async (uid) => {
        const r = await readDocument({
            find: { _id: uid },
            path: EnginePath.userAcct
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

        if (!r) throw simplifyError('user_not_found', 'This user was not found on our database record').simpleError;
        return { ...r, uid };
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
        sneakSignupAuth,
        googleAuthConfig,
        appleAuthConfig,
        facebookAuthConfig,
        githubAuthConfig,
        twitterAuthConfig,
        fallbackAuthConfig,
        externalAddress,
        hostname,
        maxRequestBufferSize,
        maxUploadBufferSize
    } = config;

    if (!projectName?.trim() || typeof projectName.trim() !== 'string')
        throw '"projectName" is required in MosquitoDbServer() constructor';

    if (!accessKey?.trim() || typeof accessKey.trim() !== 'string')
        throw '"accessKey" is required in MosquitoDbServer() constructor';

    if (projectNameWrongChar.filter(v => projectName.includes(v)).length)
        throw `projectName must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (projectNameWrongChar.filter(v => `${port || ''}`.includes(v)).length)
        throw `port must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (maxRequestBufferSize && (!IS_WHOLE_NUMBER(maxRequestBufferSize) || maxRequestBufferSize < one_mb * 20))
        throw '"maxRequestBufferSize" is must be a positive whole number greater/equal to 20mb';

    if (maxUploadBufferSize && (!IS_WHOLE_NUMBER(maxUploadBufferSize) || maxUploadBufferSize < one_mb * 20))
        throw '"maxUploadBufferSize" is must be a positive whole number greater/equal to 20mb';

    if (databaseRules && typeof databaseRules !== 'function')
        throw `databaseRules type must be function but got ${typeof databaseRules}`;

    if (storageRules && typeof storageRules !== 'function')
        throw `storageRules type must be function but got ${typeof storageRules}`;

    if ((signerKey?.trim() || '').length !== 90 || typeof signerKey?.trim() !== 'string')
        throw `signerKey must have string length equals to 90 characters without spaces`;

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
    if (externalAddress && typeof externalAddress !== 'string') throw `externalAddress must be a string`;
    if (hostname && typeof hostname !== 'string') throw `hostname must be a string`;

    if (sneakSignupAuth && typeof sneakSignupAuth !== 'function') throw 'sneakSignupAuth must be a function';

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