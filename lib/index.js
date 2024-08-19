import express from "express";
import compression from "compression";
import { databaseLivePath, databaseLiveRoutes, databaseRoutes, emitDatabase, readDocument, writeDocument } from "./products/database/index.js";
import { authLivePath, authLiveRoutes, authRoutes } from "./products/auth/index.js";
import { removeVideoFreezer, storageRoutes } from "./products/storage/index.js";
import { Scoped } from "./helpers/variables.js";
import { decodeBinary, deserializeE2E, getStringExtension, interpolate, niceTry, serializeE2E } from "./helpers/utils.js";
import { getDB } from "./products/database/base.js";
import { releaseTokenSelfDestruction, validateJWT, verifyJWT } from "./products/auth/tokenizer.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, DEFAULT_DB, EnginePath, EngineRoutes, STORAGE_FREEZER_DIR, STORAGE_PATH, STORAGE_PREFIX_PATH, STORAGE_ROUTE, STORAGE_URL_TO_FILE, one_hour, one_mb, one_minute } from "./helpers/values.js";
import { validateGoogleAuthConfig } from "./products/auth/google_auth.js";
import { validateAppleAuthConfig } from "./products/auth/apple_auth.js";
import { validateFacebookAuthConfig } from "./products/auth/facebook_auth.js";
import { validateGithubAuthConfig } from "./products/auth/github_auth.js";
import { validateTwitterAuthConfig } from "./products/auth/twitter_auth.js";
import { validateFallbackAuthConfig } from "./products/auth/custom_auth.js";
import { DisconnectionWriteTaskListener, SignoutUserSignal, StorageListener, UserCountReadyListener } from "./helpers/listeners.js";
import { Server } from "socket.io";
import http from 'http';
import { mkdir, readFile, unlink, writeFile, rm } from "fs/promises";
import { cleanUserToken } from "./products/auth/email_auth.js";
import { invalidateToken } from "./products/auth/email_auth.js";
import cors from 'cors';
import { parse, stringify } from 'json-buffer';
import { exec } from "child_process";
import { createRequire } from 'node:module';
import { MongoClient } from "mongodb";
import naclPkg from 'tweetnacl';
import { simplifyCaughtError, simplifyError } from 'simplify-error';
import { Validator } from "guard-object";
import { extractBackup as thatExtractBackup } from "../bin/extract_backup.js";
import { installBackup as thatInstallBackup } from '../bin/install_backup.js';

const { sign: e2eSign } = naclPkg;

const _require = createRequire(import.meta.url);

const PORT = process.env.MOSQUITO_PORT || 4291;

const serveStorage = ({
    projectName,
    logger,
    staticContentCacheControl,
    staticContentMaxAge,
    staticContentProps,
    transformMediaRoute: mediaRoute,
    transformMediaCleanupTimeout
}) => async (req, res, next) => {
    const route = req.url;

    if (typeof route === 'string' && route.startsWith(`${STORAGE_ROUTE}/`)) {
        const now = Date.now(),
            hasLogger = logger.includes('all') || logger.includes('served-content');

        if (hasLogger) console.log('started route: ', route);

        const { 'mosquito-token': authToken } = req.headers,
            auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : null,
            cleanRoute = route.substring(`${STORAGE_ROUTE}/`.length),
            routeExtension = getStringExtension(cleanRoute);

        const rulesObj = {
            ...(auth ? { auth: { ...auth, token: authToken } } : {}),
            request: req,
            endpoint: 'serveFile',
            prescription: {
                path: cleanRoute
            }
        };

        try {
            await Scoped.InstancesData[projectName].storageRules?.(rulesObj);
        } catch (e) {
            res.status(403).send({
                status: 'error',
                ...simplifyError('security_error', `${e}`)
            });
            return;
        }

        const routeTransformer = mediaRoute === '*' ||
            (mediaRoute || []).find(({ route }) =>
                (route instanceof RegExp ? route.test(cleanRoute) : cleanRoute.startsWith(route))
            ),
            linkRef = new URL(req.url, `http://${req.headers.host}`),
            filePath = STORAGE_URL_TO_FILE(linkRef.href, projectName),
            partern = {};

        [
            [['w', 'width'], (v) => isNaN(v * 1) ? undefined : v * 1],
            [['h', 'height'], (v) => isNaN(v * 1) ? undefined : v * 1],
            [['gray', 'grayscale'], (v) => v === '1' || v === 'true' || undefined],
            [['b', 'blur'], (v) =>
                v === 'true' || (isNaN(v * 1) ? undefined : v * 1)
            ],
            [['f', 'fit'], (v) => isNaN(v * 1) ? undefined : v * 1],
            [['t', 'top'], (v) => isNaN(v * 1) ? undefined : v * 1],
            [['l', 'left'], (v) => isNaN(v * 1) ? undefined : v * 1],
            [['mute'], (v) => v === '1' || v === 'true' || undefined],
            [['flip'], (v) => v === '1' || v === 'true' || undefined],
            [['flop'], (v) => v === '1' || v === 'true' || undefined],
            [['o', 'format'], (v) => v],
            [['q', 'quality'], (v) => {
                const x = v * 1;
                return (isNaN(x) || x > 1 || x < 0) ? undefined : x * 100;
            }],
            [['loss', 'lossless'], (v) => v === '1' || v === 'true' || undefined],
            [['vbr'], v => v],
            [['abr'], v => v],
            [['fps'], v => isNaN(v * 1) ? undefined : v * 1],
            [['preset'], v => v]
        ].forEach(([paths, ext]) => {
            const v = paths.map(v => ext(linkRef.searchParams.get(v) || undefined)).filter(v =>
                v !== undefined
            )[0];

            if (v !== undefined) partern[paths.slice(-1)[0]] = v;
        });

        if (routeTransformer) {
            const mediaType = getMediaType(routeExtension),
                localBuffer = await niceTry(() => readFile(filePath));
            let rib;

            try {
                if (localBuffer) {
                    if (routeTransformer?.transform) {
                        rib = await routeTransformer.transform({ request: req, localBuffer });
                        if (res.headersSent) return;
                    } else if (
                        (mediaType === 'image' || mediaType === 'video' || routeTransformer?.transformAs) &&
                        Object.keys(partern).length
                    ) {
                        // console.log('transforming partern:', partern);
                        const { width, height, grayscale, blur, fit, top, left, flip, flop, format, quality, lossless, mute, vbr, abr, preset, fps } = partern;

                        if (mediaType === 'image' || routeTransformer?.transformAs === 'image') {
                            const SharpLib = _require('sharp');
                            let sharpInstance = SharpLib(localBuffer);

                            if (top || left) {
                                sharpInstance = sharpInstance.extract({ width, height, top, left });
                            } else if (fit || width || height)
                                sharpInstance = sharpInstance.resize({ fit, height, width });

                            if (grayscale) sharpInstance = sharpInstance.grayscale(grayscale);
                            if (blur) sharpInstance = sharpInstance.blur(blur);
                            if (flip) sharpInstance = sharpInstance.flip(flip);
                            if (flop) sharpInstance = sharpInstance.flop(flop);
                            if (format || quality || lossless) {
                                sharpInstance = sharpInstance.toFormat(format || (await sharpInstance.metadata()).format, {
                                    lossless, quality
                                });
                            }

                            rib = await sharpInstance.toBuffer();
                        } else {
                            const com = [],
                                crf = (quality || lossless) ? ' -crf ' + (quality ? interpolate(quality, [51, 0], [0, 100]) : 999) : '',
                                outTipDir = STORAGE_FREEZER_DIR(projectName),
                                outPath = `${outTipDir}/${encodeURIComponent(linkRef.href)}${routeExtension ? '.' + routeExtension : ''}`;

                            if (flip) com.push('vflip');
                            if (flop) com.push('hflip');
                            if (top || left) {
                                com.push(`crop=${width}:${height}:${top}:${left}`);
                            } else if (width || height)
                                com.push(`scale=${width || -1}:${height || -1}`);
                            if (grayscale) com.push(`colorchannelmixer=0.299:0.587:0.114`);

                            if (Scoped.cacheTranformVideoTimer[outPath]?.timer) {
                                Scoped.cacheTranformVideoTimer[outPath].timer.refresh();
                                rib = outPath;
                            } else {
                                rib = await new Promise(async (resolve, reject) => {
                                    if (Scoped.cacheTranformVideoTimer[outPath]?.processing) {
                                        if (!Scoped.cacheTranformVideoTimer[outPath].processList)
                                            Scoped.cacheTranformVideoTimer[outPath].processList = [];

                                        Scoped.cacheTranformVideoTimer[outPath].processList.push([resolve, reject]);
                                        return;
                                    }
                                    Scoped.cacheTranformVideoTimer[outPath] = {
                                        processing: true,
                                        inputFile: filePath
                                    };

                                    const ffmpegCommad = `ffmpeg -i "${filePath}"${mute ? ' -an' : ''}${com.length ? ' -vf "' + com.join(', ') + '"' : ''}${mute ? '' : ' -c:a copy'}${crf}${vbr ? ' -b:v ' + vbr : ''}${abr ? ' -b:a' + abr : ''}${fps ? ' -r' + fps : ''} -preset ${preset || 'medium'} "${outPath}"`;

                                    exec(ffmpegCommad, async (err) => {
                                        if (!Scoped.cacheTranformVideoTimer[outPath]) {
                                            reject(err || new Error('file was updated in transit'));
                                            return;
                                        }
                                        if (err) {
                                            reject(err);
                                            Scoped.cacheTranformVideoTimer[outPath].processList?.map?.(([_, deny]) => deny(err));
                                            delete Scoped.cacheTranformVideoTimer[outPath];
                                            await niceTry(() => unlink(outPath));
                                        } else {
                                            Scoped.cacheTranformVideoTimer[outPath].timer = setTimeout(async () => {
                                                clearTimeout(Scoped.cacheTranformVideoTimer[outPath].timer);
                                                delete Scoped.cacheTranformVideoTimer[outPath];
                                                await niceTry(() => unlink(outPath));
                                            }, transformMediaCleanupTimeout || (one_hour * 7));
                                            resolve(outPath);
                                            Scoped.cacheTranformVideoTimer[outPath].processList?.map?.(([done]) => done(outPath));
                                            delete Scoped.cacheTranformVideoTimer[outPath].processing;

                                            if (Scoped.cacheTranformVideoTimer[outPath].processList)
                                                delete Scoped.cacheTranformVideoTimer[outPath].processList;
                                        }
                                    });
                                });
                            }
                        }
                    } else rib = null;
                }
            } catch (e) {
                res.status(500).send(simplifyCaughtError(e).simpleError);
                if (e && hasLogger) console.log(`${route} err: ${e}`);
                if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
                return;
            }

            if (typeof rib === 'string') {
                sendFile(rib);
                return;
            } else if (Buffer.isBuffer(rib)) {
                res.status(200).end(rib);
                if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
                return;
            } else if (rib !== null) {
                res.sendStatus(404);
                if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
                return;
            }
        }

        function sendFile(path) {
            res.sendFile(path, {
                ...staticContentProps,
                ...staticContentMaxAge === undefined ? {} : { maxAge: staticContentMaxAge },
                ...staticContentCacheControl === undefined ? {} : { cacheControl: staticContentCacheControl }
            }, (err) => {
                // console.log('serveStorage: ', err);
                // if (err) {
                //     // res.status(404).send({ status: 'error', ...simplifyError('unexpected_error', `${err}`) });
                // } else
                //  res.status().end();
                if (err && hasLogger) console.log(`${route} err: ${err}`);
                if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
            });
        }
        sendFile(filePath);
    } else next();
}

const getMediaType = (fileExtension) => {
    const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'];
    const videoExtensions = ['mp4', 'mov', 'avi', 'mkv', 'wmv', 'flv'];

    const lowerCaseExtension = (fileExtension || '').toLowerCase();

    if (imageExtensions.includes(lowerCaseExtension)) {
        return 'image';
    } else if (videoExtensions.includes(lowerCaseExtension)) {
        return 'video';
    } else {
        return 'unknown';
    }
}

const areYouOk = (req, res, next) => {
    if (req.url === `/${EngineRoutes._areYouOk}`) {
        res.status(200).send({ status: 'yes' });
        return;
    }
    next();
}

const useMosquitoServer = (app, config) => {
    const { projectName, port, accessKey, logger, staticContentCacheControl, staticContentMaxAge, staticContentProps, externalAddress, corsOrigin, maxRequestBufferSize, maxUploadBufferSize, onSocketSnapshot, enforceE2E_Encryption, transformMediaRoute, preMiddlewares, transformMediaCleanupTimeout, onUserMounted } = config;

    app.disable("x-powered-by");

    const reqBufferLimiter = [
        express.json({ type: '*/json', limit: maxRequestBufferSize || '100MB' }),
        express.text({ type: 'text/plain', limit: maxRequestBufferSize || '100MB' })
    ];

    [
        ...Array.isArray(preMiddlewares) ? preMiddlewares : preMiddlewares ? [preMiddlewares] : [],
        (req, _, next) => {
            if (req.url?.startsWith?.(`/${projectName}/`)) {
                req.rawBody = new Promise(resolve => {
                    const buf = [];
                    req.on('data', x => {
                        buf.push(x);
                    });
                    req.on('end', () => {
                        resolve(Buffer.concat(buf));
                    });
                });
            }
            next();
        },
        ...(corsOrigin === undefined ? [] : [cors({ origin: corsOrigin })]),
        compression(),
        areYouOk,
        serveStorage({
            projectName,
            logger,
            staticContentCacheControl,
            staticContentMaxAge,
            staticContentProps,
            transformMediaRoute,
            transformMediaCleanupTimeout
        }),
        ...reqBufferLimiter,
        (req, _, next) => {
            const authToken = req.headers['mosquito-token'];
            if (authToken) req.headers.mtoken = authToken;
            next();
        },
        ...authRoutes({ ...config }),
        ...databaseRoutes({ ...config }),
        express.text({ type: 'text/plain', limit: maxUploadBufferSize || '10GB' }),
        express.raw({ type: 'buffer/upload', limit: maxUploadBufferSize || '10GB' }),
        ...storageRoutes({ projectName, logger, externalAddress, accessKey }),
        ...reqBufferLimiter,
        async (req, _, next) => {
            if (req.rawBody) req.rawBody = await req.rawBody;
            next();
        }
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

    io.on('connection', async socket => {
        const initAuthHandshake = socket.handshake.auth;
        const scope = {},
            restrictedRoute = [
                ...authLivePath,
                ...databaseLivePath
            ],
            // https://socket.io/docs/v3/emit-cheatsheet/#reserved-events
            reservedEventName = [
                'connect',
                'connect_error',
                'disconnect',
                'disconnecting',
                'newListener',
                'removeListener'
            ];

        authLiveRoutes({ ...config }).map(e => e(socket, scope));
        databaseLiveRoutes({ ...config }).map(e => e(socket, scope));

        if (initAuthHandshake?._m_internal || !onSocketSnapshot) {
            if (initAuthHandshake?._from_base) {
                const token = initAuthHandshake?.atoken;
                let thisUser = token && validateJWT(token, projectName),
                    unmountUser,
                    hasDisconnected;

                const signoutSignal = thisUser ? SignoutUserSignal.listenTo('d', async uid => {
                    try {
                        if (
                            uid &&
                            uid === (await thisUser)?.uid &&
                            !hasDisconnected
                        ) socket.emit('_signal_signout');
                    } catch (error) { }
                }) : undefined;

                socket.on('disconnect', () => {
                    hasDisconnected = true;
                    signoutSignal?.();
                    unmountUser?.();
                });
                if (thisUser) {
                    try {
                        const user = await thisUser;
                        if (!hasDisconnected)
                            unmountUser = onUserMounted?.({ user, headers: socket.request.headers });
                    } catch (error) { }
                }
            }
            return;
        }
        try {
            const { e2e, ugly, accessKey: ak } = initAuthHandshake;

            if (enforceE2E_Encryption && !ugly)
                throw 'Runtime error: encryption was enforced on this server, but incoming request doesn\'t seem encrypted';

            let mtoken, clientPublicKey, extraAuth;

            if (ugly) {
                const [body, clientKey, atoken] = deserializeE2E(e2e, projectName);
                mtoken = atoken;
                clientPublicKey = clientKey;
                if (body.accessKey !== accessKey)
                    throw simplifyError('incorrect_access_key', 'The accessKey provided is not correct');
                extraAuth = body.a_extras;
            } else {
                mtoken = initAuthHandshake.mtoken;
                extraAuth = initAuthHandshake.a_extras;
                if (ak !== accessKey)
                    throw simplifyError('incorrect_access_key', 'The accessKey provided is not correct');
            }

            const listenersFuncObj = {};

            ['on', 'once', 'prependOnceListener'].forEach(e => {
                listenersFuncObj[e] = (route, callback, onError) => {
                    if (restrictedRoute.includes(route))
                        throw `${route} is a restricted socket path, avoid using any of ${restrictedRoute}`;

                    socket.on(route, async function () {
                        if (reservedEventName.includes(route)) {
                            callback?.(...[...arguments]);
                            return;
                        }
                        const [emittion, ...restArgs] = [...arguments];

                        let reqBody, clientPublicKey;

                        try {
                            if (ugly) {
                                const [body, clientKey] = deserializeE2E(emittion, projectName);
                                reqBody = parse(body);
                                clientPublicKey = clientKey;
                            } else reqBody = emittion;
                            if (!Array.isArray(reqBody))
                                throw simplifyError('invalid_argument_result', 'The request body was not deserialized correctly');
                        } catch (e) {
                            onError?.(simplifyCaughtError(e)?.simpleError);
                            return;
                        }

                        callback?.(...reqBody, ...typeof restArgs[0] === 'function' ? [function () {
                            const args = [...arguments];
                            let res;

                            if (ugly) {
                                res = serializeE2E(stringify(args), clientPublicKey, projectName);
                            } else res = args;
                            restArgs[0](res);
                        }] : []);
                    });
                }
            });

            const emitEvent = async ({ emittion, timeout, promise }) => {
                const [route, ...restEmit] = emittion;

                if (typeof route !== 'string')
                    throw `expected ${promise ? 'emitWithAck' : 'emit'} first argument to be a string type`;

                const lastEmit = restEmit.slice(-1)[0],
                    mit = typeof lastEmit === 'function' ? restEmit.slice(0, -1) : restEmit;

                if (typeof lastEmit === 'function' && promise)
                    throw 'emitWithAck cannot have function in it parameter';

                const reqBuilder = ugly ? serializeE2E(stringify(mit), clientPublicKey, projectName) : null;

                const p = await (isNaN(timeout) ? socket : socket.timeout(timeout))[promise ? 'emitWithAck' : 'emit'](
                    route,
                    ...ugly ? [reqBuilder] : [mit],
                    ...typeof lastEmit === 'function' ? [function () {
                        const args = [...arguments][0];
                        let res;

                        if (ugly) {
                            res = parse(deserializeE2E(args, projectName)[0]);
                        } else res = args;

                        lastEmit(...res || []);
                    }] : []
                );

                if (p && promise) return ugly ? parse(deserializeE2E(p, projectName)[0])[0] : p[0];
            }

            const clonedSocket = {
                ...listenersFuncObj,
                handshake: {
                    ...socket.handshake,
                    auth: { ...extraAuth },
                    userToken: mtoken
                },
                emit: function () {
                    emitEvent({ emittion: [...arguments] });
                },
                emitWithAck: function () {
                    return emitEvent({ emittion: [...arguments], promise: true });
                },
                timeout: (timeout) => ({
                    emitWithAck: function () {
                        return emitEvent({ emittion: [...arguments], timeout, promise: true });
                    }
                })
            };
            onSocketSnapshot(clonedSocket);
        } catch (e) {
            onSocketSnapshot?.(undefined, simplifyCaughtError(e).simpleError);
        }
    });

    server.listen(port, () => {
        console.log(`mosquito-transport server listening on port ${port}`);
    });
}


export default class MosquitoTransportServer {
    constructor(configx) {
        const config = {
            ...configx,
            logger: (Array.isArray(configx.logger) ? configx.logger : [configx.logger]).filter(v => v),
            externalAddress: configx.externalAddress || `http://${configx.hostname || 'localhost'}:${configx.port || PORT}`,
            enforceE2E_Encryption: configx.enforceE2E
        };
        validateServerConfig(config, this);

        const {
            signerKey,
            storageRules,
            databaseRules,
            port,
            enableSequentialUid,
            accessKey,
            logger,
            externalAddress,
            uidLength,
            accessTokenInterval,
            refreshTokenExpiry,
            e2eKeyPair,
            dumpsterPath,
            mongoInstances
        } = config;

        this.externalAddress = externalAddress;
        this.projectName = config.projectName.trim();
        this.port = port || PORT;

        if (Scoped.serverInstances[this.projectName])
            throw `Cannot initialize ${this.constructor.name}() with projectName:"${this.projectName}" multiple times`;

        if (Scoped.expressInstances[`${this.port}`])
            throw `Port ${this.port} is currently being used by another ${this.constructor.name}() instance`;

        Scoped.InstancesData[this.projectName] = {
            externalAddress,
            mongoInstances,
            E2E_BufferPair: (e2eKeyPair || []).map(v => Buffer.from(v, 'base64')),
            accessTokenInterval,
            refreshTokenExpiry,
            signerKey,
            uidLength,
            dumpsterPath,
            enableSequentialUid: !!enableSequentialUid,
            databaseRules,
            storageRules
        };

        Scoped.expressInstances[`${this.port}`] = express();

        getDB(this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL).collection(EnginePath.userAcct).estimatedDocumentCount({}).then(n => {
            Scoped.SequentialUid[this.projectName] = n;
            UserCountReadyListener.dispatch(this.projectName);
        });

        useMosquitoServer(Scoped.expressInstances[`${this.port}`], {
            ...config,
            projectName: this.projectName,
            port: this.port,
            accessKey,
            logger
        });

        this.config = config;
        releaseTokenSelfDestruction(this.projectName);

        (async () => {
            try {
                await rm(`${STORAGE_PREFIX_PATH(this.projectName)}/.vid_freezer`, {
                    recursive: true,
                    force: true
                });
            } catch (e) { }
            await mkdir(STORAGE_FREEZER_DIR(this.projectName), { recursive: true });
        })()
    }

    get storagePath() {
        return STORAGE_PATH(this.projectName);
    }

    get sampleE2E() {
        const keyPair = e2eSign.keyPair();
        return [
            keyPair.publicKey,
            keyPair.secretKey
        ].map(v => Buffer.from(v).toString('base64'));
    }

    get express() {
        return Scoped.expressInstances[`${this.port}`];
    }

    signOutUser = async (uid) => {
        const db = getDB(this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        await Promise.all([
            db.collection(EnginePath.refreshTokenStore).deleteMany({ uid }),
            db.collection(EnginePath.tokenStore).deleteMany({ uid })
        ]);
        SignoutUserSignal.dispatch('d', uid);
    }

    parseToken = (token) => JSON.parse(decodeBinary(token.split('.')[1]));
    verifyToken = (token, isRefreshToken) => verifyJWT(token, this.projectName, isRefreshToken);
    validateToken = (token, isRefreshToken) => validateJWT(token, this.projectName, isRefreshToken);
    invalidateToken = (token, isRefreshToken) => invalidateToken(token, this.projectName, isRefreshToken);

    linkToFile = (link) => STORAGE_URL_TO_FILE(link, this.projectName);

    getDatabase = (dbName, dbUrl) => getDB(this.projectName, dbName, dbUrl);

    listenHttpsRequest = (route = '', callback, options) => {
        Scoped.expressInstances[`${this.port}`].use(
            express.Router({ caseSensitive: true }).all(`/${this.projectName}${route.startsWith('/') ? '' : '/'}${route}`, async (req, res) => {
                const { mtoken, authorization, uglified } = req.headers;
                const enforceUser = options?.enforceVerifiedUser || options?.enforceUser,
                    { logger, accessKey } = this.config,
                    hasLogger = logger.includes('all') || logger.includes('external-requests'),
                    now = Date.now();

                if (hasLogger) console.log(`started route: /${req.url}`);

                if (options?.rawEntry) {
                    try {
                        await callback(req, res);
                    } catch (e) {
                        console.error(`${route} routeErr: `, e);
                        if (!res.headersSent) res.end();
                    }
                    if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
                } else {
                    let auth,
                        authToken = mtoken,
                        reqBody = req.body,
                        clientPublicKey;

                    try {
                        // decrypt message
                        if (options?.enforceE2E && !uglified)
                            throw simplifyError('encryption_required', 'All request sent to this endpoint must be encrypted');

                        if (uglified) {
                            const [body, clientKey, atoken] = deserializeE2E(req.body, this.projectName);
                            clientPublicKey = clientKey;
                            authToken = atoken;
                            const initContentType = req.headers["init-content-type"];

                            try {
                                reqBody = initContentType === 'application/json'
                                    ? (niceTry(() => JSON.parse(body)) || {}) : body;
                            } catch (e) { req.body = undefined; }
                        }

                        req.body = reqBody;

                        if (authToken && (enforceUser || options?.validateUser)) {
                            auth = await validateJWT(authToken, this.projectName);
                        } else if (enforceUser) throw simplifyError('unauthorize_access', 'Only authorized users can access this request');

                        if (options?.enforceVerifiedUser && !auth?.emailVerified)
                            throw simplifyError('unverified_email', 'User email is not verified, Please verify and try again');

                        if (authorization !== `Bearer ${accessKey}`)
                            throw simplifyError('incorrect_access_key', 'The accessKey provided is not correct');
                    } catch (e) {
                        console.error(`${route} error:`, e);

                        res.status(403).appendHeader(
                            'simple_error',
                            JSON.stringify(simplifyCaughtError(e).simpleError || {})
                        ).send({ status: 'error' });
                        return;
                    }

                    try {
                        const sendResult = (s, obj) => {
                            return s.send(uglified ? {
                                e2e: serializeE2E(Validator.JSON(obj) ? JSON.stringify(obj) : obj, clientPublicKey, this.projectName)
                            } : obj);
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
                }
            })
        );
    }

    listenDatabase = (path, callback, options) => {
        const { dbName, dbUrl } = options || {},
            { logger } = this.config;

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
            removeVideoFreezer(directory);
            await niceTry(() => mkdir(tipDir, { recursive: true }));
            await writeFile(directory, buffer);

            return downloadUrl;
        } catch (e) {
            throw simplifyCaughtError(e).simpleError;
        }
    }

    deleteFile = async (path = '') => {
        path = (path.startsWith('http://') || path.startsWith('https://')) ?
            STORAGE_URL_TO_FILE(path, this.projectName) : `${STORAGE_PATH(this.projectName)}/${path}`;

        removeVideoFreezer(path);
        await unlink(path);
    }

    deleteFolder = async (path = '') => {
        path = `${STORAGE_PATH(this.projectName)}/${path}`;

        removeVideoFreezer(path, true);
        await rm(path, {
            recursive: true,
            force: true
        });
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
        if (!Validator.OBJECT(profile)) throw `profile requires a raw object value`;

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

        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;

        if (Object.keys(updateSet).length || Object.keys(updateUnset).length)
            await writeDocument({
                scope: 'updateOne',
                find: { _id: uid },
                path: EnginePath.userAcct,
                value: {
                    ...Object.keys(updateSet).length ? { $set: updateSet } : {},
                    ...Object.keys(updateUnset).length ? { $unset: updateUnset } : {}
                }
            }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    }

    updateUserMetadata = async (uid, metadata) => {
        if (!Validator.OBJECT(metadata)) throw `metadata requires a raw object value`;

        const updateSet = Object.fromEntries(
            Object.entries(metadata).map(([k, v]) =>
                v !== undefined && [`metadata.${k}`, v]
            ).filter(v => v)
        );
        const updateUnset = Object.fromEntries(
            Object.entries(metadata).map(([k, v]) =>
                v === undefined && [`metadata.${k}`, true]
            ).filter(v => v)
        );

        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;

        if (Object.keys(updateSet).length || Object.keys(updateUnset).length)
            await writeDocument({
                scope: 'updateOne',
                find: { _id: uid },
                path: EnginePath.userAcct,
                value: {
                    ...Object.keys(updateSet).length ? { $set: updateSet } : {},
                    ...Object.keys(updateUnset).length ? { $unset: updateUnset } : {}
                }
            }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    }

    updateUserClaims = async (uid, claims) => {
        if (!Validator.OBJECT(claims)) throw `profile requires a raw object value`;

        const updateSet = Object.fromEntries(
            Object.entries(metadata).map(([k, v]) =>
                v !== undefined && [`claims.${k}`, v]
            ).filter(v => v)
        );
        const updateUnset = Object.fromEntries(
            Object.entries(metadata).map(([k, v]) =>
                v === undefined && [`claims.${k}`, true]
            ).filter(v => v)
        );

        if (typeof uid !== 'string' || !uid.trim()) throw `uid requires a string value`;

        if (Object.keys(updateSet).length || Object.keys(updateUnset).length)
            await writeDocument({
                scope: 'updateOne',
                find: { _id: uid },
                path: EnginePath.userAcct,
                value: {
                    ...Object.keys(updateSet).length ? { $set: updateSet } : {},
                    ...Object.keys(updateUnset).length ? { $unset: updateUnset } : {}
                }
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

    extractBackup(config) {
        const { password, onMongodbOption } = { ...config };
        const newConfig = {
            storage: this.storagePath,
            password,
            onMongodbOption,
            database: {}
        };

        const { mongoInstances } = Scoped.InstancesData[projectName];

        Object.entries(mongoInstances).forEach(([_, dbObj]) => {
            const { defaultName, instance } = dbObj;
            const dbUrl = `mongodb://${instance.options.hosts}:${instance.options.localPort}`;

            if (!newConfig.database[dbUrl])
                newConfig.database[dbUrl] = {};
            if (!newConfig.database[dbUrl][defaultName])
                newConfig.database[dbUrl][defaultName] = '*';
        });

        return thatExtractBackup(newConfig);
    }

    installBackup(config) {
        return new Promise((resolve, reject) => {
            const { password, onMongodbOption } = { ...config };

            const installationStream = thatInstallBackup({
                password,
                storage: this.storagePath,
                onMongodbOption
            }, resolve);

            installationStream.on('error', err => {
                reject(err);
            });
        });
    }
}

const projectNameWrongChar = ['/', '\\', '.', '$', '%', '#', '!', '*', '?'];
const loggerOptions = ['all', 'auth', 'database', 'storage', 'external-requests', 'served-content', 'database-snapshot'];

const validateResizableMediaRoute = (v) => {
    if (v !== '*') {
        if (!Array.isArray(v)) throw '"transformMediaRoute" expected either "*" or an array';
        v.forEach((v, i) => {
            if (!(v?.route instanceof RegExp) && typeof v?.route !== 'string')
                throw `"transformMediaRoute" array at index ${i} expected "route" to be either RegularExpression or string but got ${v?.route}`;
            if (v?.transform !== undefined && typeof v?.transform !== 'function')
                throw `"transformMediaRoute" array at index ${i} expected "transform" to be a function`;
            if (v?.transformAs !== undefined && v.transformAs !== 'image' && v.transformAs !== 'video')
                throw `"transformAs" must be either "image" or "video" but got "${v.transformAs}"`;
        });
    }
}

const validateServerConfig = (config, that) => {
    if (!Validator.OBJECT(config))
        throw `Expected a raw object in ${that.constructor.name}() constructor`;

    const {
        projectName,
        signerKey,
        storageRules,
        databaseRules,
        port,
        enableSequentialUid,
        accessKey,
        logger,
        mongoInstances,
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
        maxUploadBufferSize,
        uidLength,
        accessTokenInterval,
        refreshTokenExpiry,
        dumpsterPath,
        transformMediaRoute,
        e2eKeyPair,
        enforceE2E,
        preMiddlewares,
        transformMediaCleanupTimeout,
        onUserMounted
    } = config;

    if (
        transformMediaCleanupTimeout !== undefined &&
        (!Number.isInteger(transformMediaCleanupTimeout) || transformMediaCleanupTimeout <= 0)
    ) throw `"transformMediaCleanupTimeout" expected a positive integer value`
    if (
        preMiddlewares !== undefined &&
        typeof preMiddlewares !== 'function' &&
        (!Array.isArray(preMiddlewares) || preMiddlewares.filter(v => typeof v !== 'function').length)
    ) throw `"preMiddlewares" must be an array of middleware functions`;

    if (typeof projectName !== 'string' || !projectName.trim())
        throw `"projectName" is required in ${that.constructor.name}() constructor`;

    if (projectName.trim() === 'storage')
        throw `"storage" is a reserver value for "projectName"`;

    if (typeof accessKey !== 'string' || !accessKey.trim())
        throw `"accessKey" is required in ${that.constructor.name}() constructor`;

    let hasDefault, hasAdmin;
    Object.entries(mongoInstances).forEach(([key, value]) => {
        if (!(value.instance instanceof MongoClient))
            throw `"instance" is required and must be an instance of MongoClient in mongoInstance['${key}']`;

        if ((key === 'default' || key === 'admin') && !value.defaultName)
            throw `"defaultName" is required in mongoInstance['${key}']`;
        if (key === 'default') hasDefault = true;
        if (key === 'admin') hasAdmin = true;
    });

    if (!hasDefault) throw `A default mongoInstance must be provided`;
    if (!hasAdmin) throw `An admin mongoInstance must be provided`;

    if (dumpsterPath !== undefined && (typeof dumpsterPath !== 'string' || !dumpsterPath.trim() || dumpsterPath.endsWith('/')))
        throw '"dumpsterPath" must be a local path string and not end with a "/"';

    if (e2eKeyPair !== undefined && (
        !Array.isArray(e2eKeyPair) ||
        e2eKeyPair.length !== 2 ||
        e2eKeyPair.filter(v => typeof v !== 'string').length
    )) throw `"e2eKeyPair" expected an array of 2 base64 string`;

    if (enforceE2E !== undefined) {
        if (typeof enforceE2E !== 'boolean') throw `"enforceE2E" must be a boolean`;
        if (enforceE2E && !e2eKeyPair) throw `enabling "enforceE2E" requires providing a "e2eKeyPair"`;
    }

    if (transformMediaRoute !== undefined) validateResizableMediaRoute(transformMediaRoute);

    if (projectNameWrongChar.filter(v => projectName.includes(v)).length)
        throw `projectName must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (projectNameWrongChar.filter(v => `${port || ''}`.includes(v)).length)
        throw `port must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (maxRequestBufferSize && (!Validator.POSITIVE_INTEGER(maxRequestBufferSize) || maxRequestBufferSize < one_mb * 20))
        throw `"maxRequestBufferSize" is must be a positive whole number greater/equals to ${one_mb * 20}(20mb)`;

    if (maxUploadBufferSize && (!Validator.POSITIVE_INTEGER(maxUploadBufferSize) || maxUploadBufferSize < one_mb * 20))
        throw `"maxUploadBufferSize" is must be a positive whole number greater/equals to ${one_mb * 20}(20mb)`;

    if (databaseRules !== undefined && typeof databaseRules !== 'function')
        throw `databaseRules type must be function but got ${typeof databaseRules}`;

    if (storageRules !== undefined && typeof storageRules !== 'function')
        throw `storageRules type must be function but got ${typeof storageRules}`;

    if (typeof signerKey !== 'string' || signerKey.trim().length !== 90)
        throw `signerKey must have string length equals to 90 characters without spaces`;

    if (enableSequentialUid !== undefined && typeof enableSequentialUid !== 'boolean')
        throw `invalid value supplied to enableSequentialUid, expected a boolean but got ${typeof enableSequentialUid}`;

    if (mergeAuthAccount !== undefined && typeof mergeAuthAccount !== 'boolean')
        throw `invalid value supplied to mergeAuthAccount, expected a boolean but got ${typeof mergeAuthAccount}`;

    if (uidLength !== undefined && (!Validator.POSITIVE_INTEGER(uidLength) || uidLength < 10))
        throw `invalid value supplied to uidLength, expected a positive whole number greater than 9`;

    if (refreshTokenExpiry !== undefined && (
        !Validator.POSITIVE_INTEGER(refreshTokenExpiry) ||
        refreshTokenExpiry < one_hour ||
        (Validator.POSITIVE_INTEGER(accessTokenInterval) && accessTokenInterval >= refreshTokenExpiry)
    )) {
        if (Validator.POSITIVE_INTEGER(accessTokenInterval) && accessTokenInterval >= refreshTokenExpiry)
            throw '"refreshTokenExpiry" must be greater than "accessTokenInterval"';
        throw `invalid value supplied to accessTokenInterval, expected a positive whole number greater/equals than ${one_hour}(1 hour)`;
    }

    if (accessTokenInterval !== undefined && (!Validator.POSITIVE_INTEGER(accessTokenInterval) || accessTokenInterval < one_minute * 10))
        throw `invalid value supplied to accessTokenInterval, expected a positive whole number greater/equals than ${one_minute * 10}(10 minutes)`;

    if (logger && (Array.isArray(logger) ? logger : [logger]).filter(v => !loggerOptions.includes(v)).length)
        throw `invalid value supplied to logger, expected any of ${loggerOptions.join(', ')}`;
    if (externalAddress !== undefined && typeof externalAddress !== 'string') throw `externalAddress must be a string`;
    if (hostname !== undefined && typeof hostname !== 'string') throw `hostname must be a string`;

    if (sneakSignupAuth !== undefined && typeof sneakSignupAuth !== 'function')
        throw '"sneakSignupAuth" must be a function';
    if (onUserMounted !== undefined && typeof onUserMounted !== 'function')
        throw '"onUserMounted" must be a function';
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


const GEO_JSON = (lat, lng) => ({
    type: "Point",
    coordinates: [lng, lat],
});

const FIND_GEO_JSON = (location, offSetMeters, centerMeters) => ({
    $near: {
        $geometry: {
            type: "Point",
            coordinates: location.reverse()
        },
        $minDistance: centerMeters || 0,
        $maxDistance: offSetMeters
    }
});

export {
    FIND_GEO_JSON,
    GEO_JSON,
    AUTH_PROVIDER_ID
};
