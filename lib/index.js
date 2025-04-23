import express from "express";
import compression from "compression";
import { databaseLivePath, databaseLiveRoutesHandler, databaseRoutes, dbRoute, emitDatabase, readDocument, TIMESTAMP, TIMESTAMP_OFFSET, writeDocument } from "./products/database/index.js";
import { authLivePath, authLiveRoutesHandler, authRouteName, authRoutes } from "./products/auth/index.js";
import { removeVideoFreezer, storageRouteName, storageRoutes, validateStoragePath } from "./products/storage/index.js";
import { Scoped } from "./helpers/variables.js";
import { decodeBinary, deserializeE2E, encodeBinary, ensureDir, getStringExtension, interpolate, niceTry, normalizeRoute, serializeE2E } from "./helpers/utils.js";
import { getDB } from "./products/database/base.js";
import { releaseTokenSelfDestruction, validateJWT, verifyJWT } from "./products/auth/tokenizer.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, ERRORS, EnginePath, EngineRoutes, NO_CACHE_HEADER, STORAGE_DIRS, STORAGE_PREFIX_PATH, STORAGE_ROUTE, one_hour, one_mb, one_minute } from "./helpers/values.js";
import { validateGoogleAuthConfig } from "./products/auth/google_auth.js";
import { validateAppleAuthConfig } from "./products/auth/apple_auth.js";
import { validateFacebookAuthConfig } from "./products/auth/facebook_auth.js";
import { validateGithubAuthConfig } from "./products/auth/github_auth.js";
import { validateTwitterAuthConfig } from "./products/auth/twitter_auth.js";
import { validateFallbackAuthConfig } from "./products/auth/custom_auth.js";
import { SignoutUserSignal, StorageListener, UserCountReadyListener } from "./helpers/listeners.js";
import { Server } from "socket.io";
import { createServer } from 'http';
import { unlink, rm } from "fs/promises";
import { cleanUserToken } from "./products/auth/email_auth.js";
import { invalidateToken } from "./products/auth/email_auth.js";
import cors from 'cors';
import { exec } from "child_process";
import { createRequire } from 'node:module';
import { MongoClient } from "mongodb";
import naclPkg from 'tweetnacl-functional';
import { simplifyCaughtError, simplifyError } from 'simplify-error';
import { Validator } from "guard-object";
import { extractBackup as thatExtractBackup } from "../bin/extract_backup.js";
import { installBackup as thatInstallBackup } from '../bin/install_backup.js';
import { cleanupPendingHashes, deleteDir, deleteSource, getSource, readBuffer, streamReadableSource, streamWritableSource, writeBuffer } from "./products/storage/store.js";
import { join } from "path";
import { statusErrorCode, useDDOS, validateDDOS_Config } from "./helpers/ddos.js";
import mime from 'mime';
import LimitTasks from "limit-task";
import { cpus } from "os";
import { deserialize } from "entity-serializer";

const { box } = naclPkg;

const _require = createRequire(import.meta.url);

const PORT = process.env.MOSQUITO_PORT || 4291;

/**
 * 
 * @param {any} param0 
 * @returns {import("express").Handler}
 */
const serveStorage = ({
    projectName,
    logger,
    staticContentCacheControl,
    staticContentMaxAge,
    staticContentProps,
    transformMediaRoute: mediaRoute,
    transformMediaCleanupTimeout,
    ddosMap,
    maxFfmpegTasks,
    ffmpegEncoderArg,
    ipNode
}) => async (req, res, next) => {
    const route = `/${normalizeRoute(req.url)}`;

    if (typeof route === 'string' && route.startsWith(`${STORAGE_ROUTE}/`) && route.length > (STORAGE_ROUTE.length + 1)) {
        const now = Date.now(),
            hasLogger = logger.includes('all') || logger.includes('served-content');
        const hasErrorLogger = logger.includes('all') || logger.includes('error');

        if (hasLogger) console.log('started route: ', route);

        try {
            useDDOS(ddosMap, 'get', 'storage', req, ipNode);
        } catch (error) {
            res.sendStatus(429);
            return;
        }

        const { 'mosquito-token': authToken } = req.headers,
            auth = authToken && await niceTry(() => validateJWT(authToken, projectName)),
            cleanRoute = route.substring(`${STORAGE_ROUTE}/`.length),
            routeExtension = getStringExtension(cleanRoute);

        const { VID_CACHER } = STORAGE_DIRS(projectName);

        const rulesObj = {
            headers: { ...req.headers },
            ...auth ? { auth: { ...auth, token: authToken } } : {},
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
            );
        const { searchParams } = new URL(req.url, `http://${req.headers.host}`);
        const pattern = {};

        [
            [['w', 'width'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
            [['h', 'height'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
            [['gray', 'grayscale'], (v) => v === '1' || v === 'true' || undefined],
            [['b', 'blur'], (v) =>
                v === 'true' || (Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined)
            ],
            [['f', 'fit'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
            [['t', 'top'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
            [['l', 'left'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
            [['mute'], (v) => v === '1' || v === 'true' || undefined],
            [['flip'], (v) => v === '1' || v === 'true' || undefined],
            [['flop'], (v) => v === '1' || v === 'true' || undefined],
            [['o', 'format'], (v) => v],
            [['q', 'quality'], (v) => {
                const x = v * 1;
                return (!Validator.NUMBER(x) || x > 1 || x < 0) ? undefined : x * 100;
            }],
            [['loss', 'lossless'], (v) => v === '1' || v === 'true' || undefined],
            [['vbr'], v => v],
            [['abr'], v => v],
            [['fps'], v => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
            [['preset'], v => v]
        ].forEach(([paths, ext]) => {
            const v = paths.map(v => ext(searchParams.get(v) || undefined)).filter(v =>
                v !== undefined
            )[0];

            if (v !== undefined) pattern[paths.slice(-1)[0]] = v;
        });

        const storagePath = normalizeRoute(req.path).substring(STORAGE_ROUTE.length);
        const { source } = await getSource(storagePath, projectName);

        if (routeTransformer) {
            const mediaType = getMediaType(routeExtension);
            let rib;

            try {
                if (source) {
                    if (routeTransformer?.transform) {
                        rib = await routeTransformer.transform({ request: req, uri: source });
                        if (res.headersSent) return;
                    } else if (
                        (mediaType === 'image' || mediaType === 'video' || routeTransformer?.transformAs) &&
                        Object.keys(pattern).length
                    ) {
                        const { width, height, grayscale, blur, fit, top, left, flip, flop, format, quality, lossless, mute, vbr, abr, preset, fps } = pattern;

                        if (mediaType === 'image' || routeTransformer?.transformAs === 'image') {
                            const SharpLib = _require('sharp');
                            let sharpInstance = SharpLib(source);

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
                            const com = [];
                            const crf = (quality || lossless) ? ' -crf ' + (quality ? interpolate(quality, [51, 0], [0, 100]) : 999) : '';
                            const sortedPattern = Object.entries(pattern)
                                .sort((a, b) => (a > b) ? 1 : (a < b) ? -1 : 0)
                                .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join(',');

                            const outPath = join(VID_CACHER, `${encodeURIComponent(storagePath)}${sortedPattern}.${routeExtension || 'mp4'}`);

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
                                        Scoped.cacheTranformVideoTimer[outPath].processList.push([resolve, reject]);
                                        return;
                                    }
                                    Scoped.cacheTranformVideoTimer[outPath] = {
                                        processing: true,
                                        inputFile: join(VID_CACHER, storagePath),
                                        processList: [[resolve, reject]]
                                    };
                                    const taskNode = `${projectName}${maxFfmpegTasks}`;

                                    const QueueTask = Validator.POSITIVE_INTEGER(maxFfmpegTasks) &&
                                        (
                                            Scoped.FfmpegTranscodeTask[taskNode] ||
                                            (Scoped.FfmpegTranscodeTask[taskNode] = LimitTasks(maxFfmpegTasks))
                                        );

                                    const GRAPHICS_LIB = ffmpegEncoderArg ? ` -c:v ${ffmpegEncoderArg?.trim?.()}` : ` -c:v libx264 -threads ${cpus().length}`;

                                    const ffmpegCommad = `ffmpeg -i "${source}"${mute ? ' -an' : ''}${com.length ? ' -vf "' + com.join(', ') + '"' : ''}${GRAPHICS_LIB}${mute ? '' : ' -c:a copy'}${crf}${vbr ? ' -b:v ' + vbr : ''}${abr ? ' -b:a' + abr : ''}${fps ? ' -r ' + fps : ''} -preset ${preset || 'medium'} "${await ensureDir(outPath)}"`;

                                    const transcodeVideo = () =>
                                        new Promise(resolve => {
                                            exec(ffmpegCommad, (err) => {
                                                resolve();
                                                if (!Scoped.cacheTranformVideoTimer[outPath]) return;
                                                if (err) {
                                                    Scoped.cacheTranformVideoTimer[outPath].processList?.map?.(([_, deny]) => deny(err));
                                                    delete Scoped.cacheTranformVideoTimer[outPath];
                                                    unlink(outPath);
                                                } else {
                                                    Scoped.cacheTranformVideoTimer[outPath].timer = setTimeout(() => {
                                                        clearTimeout(Scoped.cacheTranformVideoTimer[outPath].timer);
                                                        delete Scoped.cacheTranformVideoTimer[outPath];
                                                        unlink(outPath);
                                                    }, transformMediaCleanupTimeout || (one_hour * 7));
                                                    Scoped.cacheTranformVideoTimer[outPath].processList.map(([done]) => done(outPath));
                                                    delete Scoped.cacheTranformVideoTimer[outPath].processing;

                                                    if (Scoped.cacheTranformVideoTimer[outPath].processList)
                                                        delete Scoped.cacheTranformVideoTimer[outPath].processList;
                                                }
                                            });
                                        });

                                    if (QueueTask) {
                                        QueueTask(transcodeVideo);
                                    } else transcodeVideo();
                                });
                            }
                        }
                    } else rib = null;
                }
            } catch (e) {
                res.status(500).send(simplifyCaughtError(e).simpleError);
                if (e && hasErrorLogger) console.log(`${route} err: ${e}`);
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
            const type = mime.lookup(req.path, 'UNKNOWN');
            if (type !== 'UNKNOWN') res.set({ 'Content-Type': type });

            res.sendFile(path, {
                ...staticContentProps,
                ...staticContentMaxAge === undefined ? {} : { maxAge: staticContentMaxAge },
                ...staticContentCacheControl === undefined ? {} : { cacheControl: staticContentCacheControl }
            }, (err) => {
                if (err && hasErrorLogger) console.log(`${route} err: ${err}`);
                if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
            });
        }
        if (source) {
            sendFile(source);
        } else {
            res.sendStatus(404);
            if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
        }
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
        res.set(NO_CACHE_HEADER);
        res.status(200).send({ status: 'yes' });
        return;
    }
    next();
};

const InternalRoutesList = [
    'e2e',
    ...dbRoute,
    ...dbRoute.map(v => `e2e/${encodeBinary(v)}`),
    ...authRouteName,
    ...authRouteName.map(v => `e2e/${encodeBinary(v)}`),
    ...storageRouteName,
    ...storageRouteName.map(v => `e2e/${encodeBinary(v)}`),
    EngineRoutes._areYouOk,
    normalizeRoute(STORAGE_ROUTE)
];

const useMosquitoServer = (app, config) => {
    const { projectName, port, corsOrigin, maxRequestBufferSize, onSocketSnapshot, onSocketError, enforceE2E_Encryption, preMiddlewares, onUserMounted } = config;

    app.disable("x-powered-by");

    [
        ...Array.isArray(preMiddlewares) ? preMiddlewares : preMiddlewares ? [preMiddlewares] : [],
        (req, _, next) => {
            const nr = normalizeRoute(req.path);
            if (!InternalRoutesList.some(r => nr === r)) {
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
        ...corsOrigin === undefined ? [] : [cors({ origin: corsOrigin })],
        compression(),
        areYouOk,
        serveStorage({ ...config }),
        express.json({ type: '*/json', limit: maxRequestBufferSize || '100MB' }),
        express.text({ type: 'text/plain', limit: maxRequestBufferSize || '100MB' }),
        express.raw({ type: 'request/buffer', limit: maxRequestBufferSize || '100MB' }),
        (req, _, next) => {
            const authToken = req.headers['mosquito-token'];
            if (authToken) req.headers.mtoken = authToken;
            next();
        },
        ...authRoutes({ ...config }),
        ...databaseRoutes({ ...config }),
        ...storageRoutes({ ...config }),
        async (req, res, next) => {
            if (req.rawBody) req.rawBody = await req.rawBody;
            if (req.headers.uglified) {
                const originalWrite = res.write;
                const originalEnd = res.end;

                const chunks = [];

                res.write = function (chunk) {
                    chunks.push(Buffer.from(chunk));
                };

                res.end = async function (chunk) {
                    if (chunk) chunks.push(Buffer.from(chunk));
                    const totalBuf = Buffer.concat(chunks);
                    const { __sender } = req;
                    const transformedBody = typeof __sender === 'function' ? await __sender(totalBuf) : totalBuf;

                    res.setHeader('Content-Length', Buffer.byteLength(transformedBody));
                    originalWrite.call(res, transformedBody);
                    originalEnd.call(res);
                };
            }
            next();
        }
    ].forEach(e => {
        app.use(e);
    });

    const server = createServer(app);
    const io = new Server(server, {
        pingTimeout: 3700,
        pingInterval: 1500,
        ...corsOrigin === undefined ? undefined : { cors: { origin: corsOrigin } },
        maxHttpBufferSize: maxRequestBufferSize || (one_mb * 100)
    });

    io.on('connection', async socket => {
        const initAuthHandshake = socket.handshake.auth;
        const scope = {};
        const restrictedRoute = [
            ...authLivePath,
            ...databaseLivePath
        ].map(v => [v, encodeBinary(v)]).flat();
        // https://socket.io/docs/v3/emit-cheatsheet/#reserved-events
        const reservedEventName = [
            'connect',
            'connect_error',
            'disconnect',
            'disconnecting',
            'newListener',
            'removeListener'
        ];

        authLiveRoutesHandler({ ...config })(socket);
        databaseLiveRoutesHandler({ ...config })(socket);

        if (initAuthHandshake?._m_internal) {
            if (initAuthHandshake?._from_base) {
                const socketHeader = socket.request.headers;
                let thatUser,
                    unmountUser,
                    hasDisconnected;

                const signoutSignal = SignoutUserSignal.listenTo('d', async uid => {
                    try {
                        if (
                            uid &&
                            uid === thatUser?.uid &&
                            !hasDisconnected
                        ) socket.emit('_signal_signout');
                    } catch (error) { }
                });

                socket.on('_update_mounted_user', async (token) => {
                    let thisUser;
                    try {
                        thisUser = token && await validateJWT(token, projectName);
                    } catch (_) { }

                    if (hasDisconnected) return;

                    if (thisUser?.uid !== thatUser?.uid) {
                        unmountUser?.();
                        unmountUser = thisUser ? onUserMounted?.({ user: thisUser, headers: socketHeader }) : undefined;
                    }
                    thatUser = thisUser || null;
                });

                socket.on('disconnect', () => {
                    hasDisconnected = true;
                    signoutSignal?.();
                    unmountUser?.();
                    unmountUser = undefined;
                });
            }
            return;
        }
        if (!onSocketSnapshot) {
            socket.disconnect();
            return;
        }
        try {
            const { e2e, ugly } = initAuthHandshake;

            if (enforceE2E_Encryption && !ugly)
                throw 'Runtime error: encryption was enforced on this instance, but incoming request doesn\'t seem encrypted';

            let mtoken, clientPublicKey, extraAuth;

            if (ugly) {
                const [body, clientKey, atoken] = await deserializeE2E(Buffer.from(e2e, 'base64'), projectName);
                mtoken = atoken;
                clientPublicKey = clientKey;
                extraAuth = body.a_extras;
            } else {
                mtoken = initAuthHandshake.mtoken;
                extraAuth = initAuthHandshake.a_extras;
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
                        const [[emittion, not_encrypted], emitable, ...rest] = [...arguments];

                        let reqBody, clientPublicKey;

                        try {
                            if (
                                (emitable !== undefined &&
                                    typeof emitable !== 'function') ||
                                rest.length
                            ) throw 'tampered socket emittion';
                            if (ugly) {
                                const [body, clientKey] = await deserializeE2E(emittion, projectName);
                                reqBody = body;
                                clientPublicKey = clientKey;
                            } else reqBody = emittion;
                            reqBody = discloseSocketArguments([reqBody, not_encrypted]);
                            if (!Array.isArray(reqBody))
                                throw simplifyError('invalid_argument_result', 'The request body was not deserialized correctly');
                        } catch (e) {
                            console.error(e);
                            onError?.({
                                ...simplifyCaughtError(e)?.simpleError,
                                auth: extraAuth,
                                data: emittion
                            });
                            return;
                        }

                        callback?.(...reqBody, ...typeof emitable === 'function' ? [async function () {
                            const [args, not_encrypted] = encloseSocketArguments([...arguments]);
                            let res;

                            if (ugly) {
                                res = await serializeE2E(args, clientPublicKey, projectName);
                            } else res = args;
                            emitable([res, not_encrypted]);
                        }] : []);
                    });
                };
            });

            const emitEvent = async ({ emittion, timeout, promise }) => {
                const [route, ...restEmit] = emittion;

                if (typeof route !== 'string')
                    throw `expected ${promise ? 'emitWithAck' : 'emit'} first argument to be a string type`;

                const lastEmit = restEmit.slice(-1)[0];
                const hasEmitable = typeof lastEmit === 'function';
                const [mit, not_encrypted] = encloseSocketArguments(hasEmitable ? restEmit.slice(0, -1) : restEmit);

                if (hasEmitable && promise)
                    throw 'emitWithAck cannot have function in it argument';

                const reqBuilder = ugly ? await serializeE2E(mit, clientPublicKey, projectName) : null;

                const result = await (timeout ? socket.timeout(timeout) : socket)[promise ? 'emitWithAck' : 'emit'](
                    route,
                    [ugly ? reqBuilder : mit, not_encrypted],
                    ...hasEmitable ? [async function () {
                        const [[args, not_encrypted]] = [...arguments];
                        let res;

                        if (ugly) {
                            res = (await deserializeE2E(args, projectName))[0];
                        } else res = args;

                        lastEmit(...discloseSocketArguments([res, not_encrypted]));
                    }] : []
                );

                if (result && promise) {
                    return discloseSocketArguments([ugly ? (await deserializeE2E(result[0], projectName))[0] : result[0], result[1]])[0];
                }
            };

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
                timeout: (timeout) => {
                    if (timeout !== undefined && !Validator.POSITIVE_INTEGER(timeout))
                        throw `expected a positive integer for timeout but got ${timeout}`;

                    return {
                        emitWithAck: function () {
                            return emitEvent({ emittion: [...arguments], timeout, promise: true });
                        }
                    };
                },
                disconnect: (...args) => {
                    socket.disconnect(...args);
                },
                disconnected: false
            };

            socket.on('disconnect', () => {
                clonedSocket.disconnected = true;
            });
            // TODO: disconnected
            onSocketSnapshot(clonedSocket);
        } catch (e) {
            onSocketError?.(Object.assign(simplifyCaughtError(e).simpleError, { socket }));
        }
    });

    server.listen(port, () => {
        console.log(`mosquito-transport server listening on port ${port}`);
    });
}

export class DoNotEncrypt {
    constructor(value) {
        this.value = value;
    }
};

const encloseSocketArguments = (args) => {
    const [encrypted, unencrypted] = [{}, {}];

    args.forEach((v, i) => {
        if (v instanceof DoNotEncrypt) {
            unencrypted[i] = v.value;
        } else encrypted[i] = v;
    });
    return [encrypted, unencrypted];
}

const discloseSocketArguments = (args = []) => {
    return args.map((obj, i) => Object.entries(obj).map(v => i ? [v[0], new DoNotEncrypt(v[1])] : v)).flat()
        .sort((a, b) => (a[0] * 1) - (b[0] * 1)).map((v, i) => {
            if (v[0] * 1 !== i) throw 'corrupted socket arguments';
            return v[1];
        });
}

export default class MosquitoTransportServer {
    constructor(configx) {
        const config = {
            ...configx,
            ddosMap: configx.ddosMap || {
                auth: {
                    signup: { calls: 7, perSeconds: 60 * 30 },
                    signin: { calls: 10, perSeconds: 60 * 10 },
                    google_signin: { calls: 7, perSeconds: 60 * 5 }
                }
            },
            castBSON: configx.castBSON === undefined || configx.castBSON,
            logger: (Array.isArray(configx.logger) ? configx.logger : [configx.logger || 'error']).filter(v => v),
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
            logger,
            externalAddress,
            uidLength,
            accessTokenInterval,
            refreshTokenExpiry,
            e2eKeyPair,
            dumpsterPath,
            mongoInstances,
            autoPurgeToken
        } = config;

        this.externalAddress = externalAddress;
        this.projectName = config.projectName.trim();
        this.port = port || PORT;

        if (Scoped.serverInstances[this.projectName])
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
            storageRules
        };

        Scoped.expressInstances[this.port] = express();

        getDB(this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL).collection(EnginePath.userAcct).estimatedDocumentCount({}).then(n => {
            Scoped.SequentialUid[this.projectName] = n;
            UserCountReadyListener.dispatch(this.projectName);
        });

        useMosquitoServer(Scoped.expressInstances[this.port], {
            ...config,
            projectName: this.projectName,
            port: this.port,
            logger
        });

        this.config = config;
        if (autoPurgeToken === undefined || autoPurgeToken) releaseTokenSelfDestruction(this.projectName);

        (async () => {
            try {
                await rm(STORAGE_DIRS(this.projectName).VID_CACHER, {
                    recursive: true,
                    force: true
                });
            } catch (_) { }
        })();
        cleanupPendingHashes(this.projectName);

        // create mongodb index
        setTimeout(() => {
            Promise.all([
                [EnginePath.userAcct, [{ email: 1 }, { [AUTH_PROVIDER_ID.GOOGLE]: 1 }]],
                [EnginePath.tokenStore, [{ uid: 1 }]],
                [EnginePath.refreshTokenStore, [{ uid: 1 }]]
            ].map(([path, indexes]) =>
                Promise.all(
                    indexes.map(d =>
                        this.getDatabase(ADMIN_DB_NAME, ADMIN_DB_URL).collection(path).createIndex(d)
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

    signOutUser = async (uid) => {
        const db = getDB(this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        await Promise.all([
            db.collection(EnginePath.refreshTokenStore).deleteMany({ uid }),
            db.collection(EnginePath.tokenStore).deleteMany({ uid })
        ]);
        SignoutUserSignal.dispatch('d', uid);
    };

    parseToken = (token) => JSON.parse(decodeBinary(token.split('.')[1]));
    verifyToken = (token, isRefreshToken) => verifyJWT(token, this.projectName, isRefreshToken);
    validateToken = (token, isRefreshToken) => validateJWT(token, this.projectName, isRefreshToken);
    invalidateToken = (token, isRefreshToken) => invalidateToken(token, this.projectName, isRefreshToken);

    getDatabase = (dbName, dbUrl) => getDB(this.projectName, dbName, dbUrl);

    listenHttpsRequest = (route, callback, options) => {
        if (typeof route !== 'string') throw `listenHttpsRequest first argument must be a string but got ${route}`;
        InternalRoutesList.forEach(e => {
            if (normalizeRoute(route) === normalizeRoute(e))
                throw `"${e}" is a reserved route used internally`;
        });
        Scoped.expressInstances[this.port].use(
            express.Router({ caseSensitive: true }).all(`/${normalizeRoute(route)}`, async (req, res) => {
                const { mtoken, uglified } = req.headers;
                const enforceUser = options?.enforceVerifiedUser || options?.enforceUser;
                const { logger } = this.config;
                const hasLogger = logger.includes('all') || logger.includes('external-requests'),
                    hasErrorLogger = logger.includes('all') || logger.includes('error'),
                    now = hasLogger && Date.now();

                if (hasLogger) console.log(`started route: /${req.url}`);
                res.set(NO_CACHE_HEADER);

                try {
                    useDDOS(this.config.ddosMap, route, 'requests', req, this.config.ipNode);
                } catch (_) {
                    res.setHeader(
                        'simple_error',
                        JSON.stringify(ERRORS.TOO_MANY_REQUEST.simpleError || {})
                    );
                    res.setHeader('Access-Control-Expose-Headers', 'simple_error');
                    res.status(429).send({ status: 'error', ...ERRORS.TOO_MANY_REQUEST });
                    return;
                }

                if (options?.rawEntry) {
                    try {
                        await callback(req, res);
                    } catch (e) {
                        if (hasErrorLogger) console.error(`errRoute: /${route} err: `, e);
                        if (!res.headersSent) res.end();
                    }
                    if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
                    return;
                }

                let auth,
                    authToken = mtoken,
                    reqBody = req.body,
                    clientPublicKey;

                try {
                    // decrypt message
                    if (options?.enforceE2E && !uglified)
                        throw ERRORS.ENCRYPTION_REQUIRED;

                    if (uglified) {
                        const [body, clientKey, atoken] = await deserializeE2E(req.body, this.projectName);
                        clientPublicKey = clientKey;
                        authToken = atoken;
                        const initContentType = req.headers["init-content-type"];

                        if (initContentType === 'application/json') {
                            try {
                                reqBody = JSON.parse(body);
                            } catch (_) { }
                        } else reqBody = body;
                    } else if (req.headers['entity-encoded'] === '1' && req.body) {
                        reqBody = deserialize(req.body);
                    }

                    req.body = reqBody;

                    if (authToken && (enforceUser || options?.validateUser)) {
                        auth = await validateJWT(authToken, this.projectName);
                        if (!options?.allowDisabledAuth && auth.disabled)
                            throw ERRORS.DISABLED_AUTH_ACCESS;
                    } else if (enforceUser) throw ERRORS.UNAUTHORIZED_ACCESS;

                    if (options?.enforceVerifiedUser && !auth?.emailVerified)
                        throw ERRORS.UNVERIFIED_EMAIL;
                } catch (e) {
                    if (hasErrorLogger) console.error(`errRoute: /${route} err:`, e);

                    res.setHeader(
                        'simple_error',
                        JSON.stringify(simplifyCaughtError(e).simpleError || {})
                    );
                    res.setHeader('Access-Control-Expose-Headers', 'simple_error');
                    res.status(statusErrorCode(e)).send({ status: 'error' });
                    return;
                }

                try {
                    if (uglified) {
                        req.__sender = async (buffer) => {
                            res.set('content-type', 'application/octet-stream');
                            return await serializeE2E(buffer, clientPublicKey, this.projectName);
                        };
                    }

                    await callback(req, res, auth ? { ...auth, token: authToken } : null);
                } catch (e) {
                    if (hasErrorLogger) console.error(`errRoute: /${route} err:`, e);
                    if (!res.headersSent) {
                        res.setHeader(
                            'simple_error',
                            JSON.stringify(simplifyCaughtError(e).simpleError || {})
                        );
                        res.setHeader('Access-Control-Expose-Headers', 'simple_error');
                        res.end();
                    }
                }
                if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
            })
        );
    };

    listenDatabase = (path, callback, options) => {
        if (typeof path !== 'string') throw `listenDatabase first argument must be a string but got ${path}`;
        const { dbName, dbUrl } = options || {},
            { logger } = this.config;

        return emitDatabase(path, async function () {
            const hasLogger = logger.includes('all') || logger.includes('database-snapshot'),
                hasErrorLogger = logger.includes('all') || logger.includes('error'),
                now = hasLogger && Date.now();
            if (hasLogger) console.log(`db-snapshot ${path}: `, arguments[0]);
            try {
                await callback?.(...arguments);
            } catch (e) {
                if (hasErrorLogger) console.error(`db-snapshot Error ${path}: `, e);
            }
            if (hasLogger) console.log(`db-snapshot ${path} took: ${Date.now() - now}ms`);
        }, this.projectName, dbName, dbUrl, options);
    };

    getStorageSource = (path) => getSource(path, this.projectName);

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
        validateStoragePath(destination);
        return readBuffer(path, this.projectName);
    }

    createReadStream = (path) => {
        validateStoragePath(destination);
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

        return StorageListener.listenTo(this.projectName, async ({ dest, ...rest }) => {
            const hasLogger = logger.includes('all') || logger.includes('storage'),
                hasErrorLogger = logger.includes('all') || logger.includes('error'),
                now = hasLogger && Date.now();

            if (hasLogger) console.log(`started listenStorage ${dest}:`);
            try {
                await callback?.({ dest, ...rest });
            } catch (e) {
                if (hasErrorLogger) console.error(`listenStorage Error ${dest}: `, e);
            }
            if (hasLogger) console.log(`listenStorage ${dest} took: ${Date.now() - now}ms`);
        });
    };

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
            await writeDocument({
                scope: 'updateOne',
                find: { _id: uid },
                path: EnginePath.userAcct,
                value: {
                    ...Object.keys(updateSet).length ? { $set: updateSet } : {},
                    ...Object.keys(updateUnset).length ? { $unset: updateUnset } : {}
                }
            }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    };

    updateUserMetadata = async (uid, metadata) => {
        if (!Validator.OBJECT(metadata)) throw 'metadata requires a raw object value';
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';

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
    };

    updateUserClaims = async (uid, claims) => {
        if (!Validator.OBJECT(claims)) throw 'claims should be an object';
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';

        const updateSet = Object.fromEntries(
            Object.entries(claims).map(([k, v]) =>
                v !== undefined && [`claims.${k}`, v]
            ).filter(v => v)
        );
        const updateUnset = Object.fromEntries(
            Object.entries(claims).map(([k, v]) =>
                v === undefined && [`claims.${k}`, true]
            ).filter(v => v)
        );

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
    };

    updateUserEmailAddress = async (uid, email) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof email !== 'string' || !email.trim()) throw 'email requires a string value';

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { email, 'profile.email': email } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        await cleanUserToken(uid, this.projectName);
    };

    updateUserPassword = async (uid, password) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof password !== 'string' || !password.trim()) throw 'email requires a string value';

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { password } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        await cleanUserToken(uid, this.projectName);
    };

    updateUserEmailVerify = async (uid, verified) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof verified !== 'boolean') throw 'updateUserEmailVerify() second argument must be a boolean';

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { emailVerified: verified } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    };

    disableUser = async (uid, disabled) => {
        if (typeof uid !== 'string' || !uid.trim()) throw 'uid requires a string value';
        if (typeof disabled !== 'boolean') throw 'disabled requires a boolean value';

        await writeDocument({
            scope: 'updateOne',
            find: { _id: uid },
            path: EnginePath.userAcct,
            value: { $set: { disabled } }
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    };

    getUserData = async (uid) => {
        const r = await readDocument({
            find: { _id: uid },
            path: EnginePath.userAcct
        }, this.projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

        if (!r) throw simplifyError('user_not_found', 'This user was not found on our database record').simpleError;
        return { ...r, uid };
    };

    extractBackup(config) {
        const { password, onMongodbOption } = { ...config };
        const newConfig = {
            storage: STORAGE_PREFIX_PATH(this.projectName),
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
    };

    installBackup(config) {
        const { password, onMongodbOption } = { ...config };

        return thatInstallBackup({
            password,
            storage: STORAGE_PREFIX_PATH(this.projectName),
            onMongodbOption
        });
    };
}

const projectNameWrongChar = ['/', '\\', '.', '$', '%', '#', '!', '*', '?'];
const loggerOptions = ['all', 'auth', 'database', 'storage', 'external-requests', 'served-content', 'database-snapshot', 'error'];

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
};

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
        logger,
        castBSON,
        mongoInstances,
        mergeAuthAccount,
        interceptNewAuth,
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
        onUserMounted,
        ddosMap,
        ipNode,
        internals,
        onSocketSnapshot,
        onSocketError,
        autoPurgeToken,
        ffmpegEncoderArg,
        maxFfmpegTasks
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

    if (maxRequestBufferSize !== undefined && (!Validator.POSITIVE_INTEGER(maxRequestBufferSize) || maxRequestBufferSize < one_mb))
        throw `"maxRequestBufferSize" must be a positive integer not lesser than ${one_mb}(1mb)`;

    if (maxUploadBufferSize !== undefined && (!Validator.POSITIVE_INTEGER(maxUploadBufferSize) || maxUploadBufferSize < 1024))
        throw `"maxUploadBufferSize" must be a positive integer not lesser than 1024 (1kb)`;

    if (databaseRules !== undefined && typeof databaseRules !== 'function')
        throw `databaseRules type must be function but got ${typeof databaseRules}`;

    if (storageRules !== undefined && typeof storageRules !== 'function')
        throw `storageRules type must be function but got ${typeof storageRules}`;

    if (onSocketSnapshot !== undefined && typeof onSocketSnapshot !== 'function')
        throw `onSocketSnapshot type must be function but got ${typeof onSocketSnapshot}`;

    if (onSocketError !== undefined && typeof onSocketError !== 'function')
        throw `onSocketError type must be function but got ${typeof onSocketError}`;

    if (typeof signerKey !== 'string' || signerKey.trim().length !== 90)
        throw `signerKey must have string length equals to 90 characters without spaces`;

    if (enableSequentialUid !== undefined && typeof enableSequentialUid !== 'boolean')
        throw `invalid value supplied to enableSequentialUid, expected a boolean but got ${typeof enableSequentialUid}`;

    if (autoPurgeToken !== undefined && typeof autoPurgeToken !== 'boolean')
        throw `invalid value supplied to autoPurgeToken, expected a boolean but got ${typeof autoPurgeToken}`;

    if (castBSON !== undefined && typeof castBSON !== 'boolean')
        throw `invalid value supplied to castBSON, expected a boolean but got ${typeof castBSON}`;

    if (mergeAuthAccount !== undefined && typeof mergeAuthAccount !== 'boolean')
        throw `invalid value supplied to mergeAuthAccount, expected a boolean but got ${typeof mergeAuthAccount}`;

    if (uidLength !== undefined && (!Validator.POSITIVE_INTEGER(uidLength) || uidLength < 10))
        throw `invalid value supplied to uidLength, expected a positive integer greater than 9`;

    if (refreshTokenExpiry !== undefined && (
        !Validator.POSITIVE_INTEGER(refreshTokenExpiry) ||
        refreshTokenExpiry < one_hour ||
        (Validator.POSITIVE_INTEGER(accessTokenInterval) && accessTokenInterval >= refreshTokenExpiry)
    )) {
        if (Validator.POSITIVE_INTEGER(accessTokenInterval) && accessTokenInterval >= refreshTokenExpiry)
            throw '"refreshTokenExpiry" must be greater than "accessTokenInterval"';
        throw `invalid value supplied to accessTokenInterval, expected a positive integer greater/equals than ${one_hour}(1 hour)`;
    }

    if (accessTokenInterval !== undefined && (!Validator.POSITIVE_INTEGER(accessTokenInterval) || accessTokenInterval < one_minute * 10))
        throw `invalid value supplied to accessTokenInterval, expected a positive integer greater/equals than ${one_minute * 10}(10 minutes)`;

    if (logger && (Array.isArray(logger) ? logger : [logger]).some(v => !loggerOptions.includes(v)))
        throw `invalid value supplied to logger, expected any of ${loggerOptions.join(', ')}`;
    if (externalAddress !== undefined && typeof externalAddress !== 'string') throw `externalAddress must be a string`;
    if (hostname !== undefined && typeof hostname !== 'string') throw `hostname must be a string`;

    if (interceptNewAuth !== undefined && typeof interceptNewAuth !== 'function')
        throw '"interceptNewAuth" must be a function';
    if (onUserMounted !== undefined && typeof onUserMounted !== 'function')
        throw '"onUserMounted" must be a function';
    if (ddosMap !== undefined) validateDDOS_Config(ddosMap);
    if (ipNode !== undefined) {
        if ((typeof ipNode !== 'string' || !ipNode.trim()) && typeof ipNode !== 'function')
            throw `expected either a non-empty string or a function at "ipNode" but got ${ipNode}`;
    }
    if (internals) {
        const features = ['database', 'auth', 'storage'];
        if (!Validator.OBJECT(internals)) throw `internals must be an object but got ${internals}`;
        Object.entries(internals).forEach(([k, v]) => {
            if (!features.includes(k)) throw `unknown property "${k}", expected any of ${k}`;
            const values = Object.values(InternalRoutes[k]);

            if (
                typeof v !== 'boolean' &&
                (!Array.isArray(v) || v.some(s => !values.includes(s)))
            ) {
                throw `expected a boolean value or an array with any of "${values}" at internals.${k} but got ${v}`;
            }
        });
    }
    if (ffmpegEncoderArg !== undefined && typeof ffmpegEncoderArg !== 'string')
        throw `ffmpegEncoderArg must be a string but got ${ffmpegEncoderArg}`;
    if (maxFfmpegTasks !== undefined && (!Validator.POSITIVE_INTEGER(maxFfmpegTasks) || maxFfmpegTasks < 1))
        throw `maxFfmpegTasks must be a positive integer greater than zero`;

    if (googleAuthConfig) validateGoogleAuthConfig(googleAuthConfig);
    if (appleAuthConfig) validateAppleAuthConfig(googleAuthConfig);
    if (facebookAuthConfig) validateFacebookAuthConfig(googleAuthConfig);
    if (githubAuthConfig) validateGithubAuthConfig(googleAuthConfig);
    if (twitterAuthConfig) validateTwitterAuthConfig(googleAuthConfig);
    if (fallbackAuthConfig) validateFallbackAuthConfig(googleAuthConfig);
};

const GEO_JSON = (lat, lng) => ({
    type: "Point",
    coordinates: [lng, lat],
});

const FIND_GEO_JSON = (location, offSetMeters, centerMeters) => ({
    $nearSphere: {
        $geometry: {
            type: "Point",
            coordinates: location.reverse()
        },
        $minDistance: centerMeters || 0,
        $maxDistance: offSetMeters
    }
});

const transformRoutes = t => Object.fromEntries(t.map(v => [v, v]));

const InternalRoutes = {
    auth: transformRoutes([...authRouteName, ...authLivePath]),
    database: transformRoutes([...dbRoute, ...databaseLivePath]),
    storage: transformRoutes(storageRouteName)
};

export {
    FIND_GEO_JSON,
    GEO_JSON,
    AUTH_PROVIDER_ID,
    InternalRoutes,
    TIMESTAMP_OFFSET,
    TIMESTAMP
};
