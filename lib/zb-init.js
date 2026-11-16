import express from "express";
import compression from "compression";
import { databaseLivePath, databaseLiveRoutesHandler, databaseRoutes, dbRoute } from "./products/database/index.js";
import { authLivePath, authLiveRoutesHandler, authRouteName, authRoutes } from "./products/auth/index.js";
import { storageRouteName, storageRoutes } from "./products/storage/index.js";
import { encodeBinary, normalizeRoute } from "./helpers/utils.js";
import { validateJWT } from "./products/auth/tokenizer.js";
import { EngineRoutes, NO_CACHE_HEADER, STORAGE_ROUTE, one_mb } from "./helpers/values.js";
import { SignoutUserSignal } from "./helpers/listeners.js";
import { Server } from "socket.io";
import { createServer } from 'http';
import cors from 'cors';
import { simplifyCaughtError } from 'simplify-error';
import { Validator } from "guard-object";
import serve from "./products/storage/serve.js";
import e2e_worker from './helpers/e2e_worker.js';

const areYouOk = (ipNode) => (req, res, next) => {
    if (req.url === `/${EngineRoutes._areYouOk}`) {
        const ipAddress = typeof ipNode === 'function' ? ipNode(req) : req[ipNode || 'ip'];
        res.set(NO_CACHE_HEADER);
        res.status(200).send({ status: 'yes', ip: ipAddress });
        return;
    }
    next();
};

export const InternalRoutesList = [
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

export const mtInit = (app, config) => {
    const {
        projectName,
        port,
        corsOrigin,
        maxRequestBufferSize,
        onSocketSnapshot,
        onSocketError,
        enforceE2E_Encryption,
        preMiddlewares,
        onUserMounted,
        pingTimeout,
        pingInterval,
        useSocketServer
    } = config;

    app.disable("x-powered-by");

    [
        ...Array.isArray(preMiddlewares)
            ? preMiddlewares
            : preMiddlewares
                ? [preMiddlewares]
                : [],
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
        ...corsOrigin === undefined ? [] : [cors(corsOrigin)],
        compression(),
        areYouOk(config?.ipNode),
        serve({ ...config }),
        express.json({ type: '*/json', limit: maxRequestBufferSize || '100MB' }),
        express.text({ type: 'text/plain', limit: maxRequestBufferSize || '100MB' }),
        express.raw({ type: 'request/buffer', limit: maxRequestBufferSize || '100MB' }),
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
    const io =
        new Server(server, {
            pingTimeout: pingTimeout || 4000,
            pingInterval: pingInterval || 1700,
            ...corsOrigin === undefined ? undefined : { cors: corsOrigin },
            maxHttpBufferSize: maxRequestBufferSize || (one_mb * 100)
        });

    const listenAuth = authLiveRoutesHandler({ ...config });
    const listenDatabase = databaseLiveRoutesHandler({ ...config });

    io.on('connection', async socket => {
        const initHandshake = socket.handshake.auth;
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

        listenAuth(socket);
        listenDatabase(socket);

        if (initHandshake?._m_internal) {
            if (initHandshake?._from_base) {
                const socketHeader = socket.request.headers;
                let thatUser,
                    unmountUser,
                    hasDisconnected;

                const signoutSignal =
                    SignoutUserSignal.listenTo('d', async uid => {
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
            const { e2e, ugly } = initHandshake;

            if (enforceE2E_Encryption && !ugly)
                throw 'Runtime error: end-to-end encryption was enforced on this instance, but incoming request doesn\'t seem encrypted';

            let mtoken, clientPublicKey, extraAuth;

            if (ugly) {
                const [body, clientKey, atoken] = await e2e_worker.decrypt(Buffer.from(e2e, 'base64'), projectName);
                mtoken = atoken;
                clientPublicKey = clientKey;
                extraAuth = body.a_extras;
            } else {
                mtoken = initHandshake.mtoken;
                extraAuth = initHandshake.a_extras;
            }

            const listenersFuncObj = {};

            ['on', 'once', 'prependOnceListener'].forEach(e => {
                listenersFuncObj[e] = (route, callback, onError) => {
                    if (restrictedRoute.includes(route))
                        throw `${route} is a restricted socket path, avoid using any of ${restrictedRoute}`;

                    socket.on(route, async function () {
                        if (reservedEventName.includes(route)) {
                            callback?.(...arguments);
                            return;
                        }
                        const [[emittion, not_encrypted], emitable, ...rest] = [...arguments];

                        let reqBody, clientPublicKey;

                        try {
                            if (
                                (emitable !== undefined && typeof emitable !== 'function') ||
                                rest.length
                            ) throw 'tampered socket emittion';

                            if (ugly) {
                                const [body, clientKey] = await e2e_worker.decrypt(emittion, projectName);
                                reqBody = body;
                                clientPublicKey = clientKey;
                            } else reqBody = emittion;
                            reqBody = discloseSocketArguments([reqBody, not_encrypted]);
                        } catch (e) {
                            console.error(e);
                            onError?.({
                                ...simplifyCaughtError(e)?.simpleError,
                                auth: extraAuth,
                                data: emittion
                            });
                            return;
                        }

                        callback?.(
                            ...reqBody,
                            ...typeof emitable === 'function'
                                ? [async function () {
                                    const [args, not_encrypted] = encloseSocketArguments([...arguments]);
                                    let res;

                                    if (ugly) {
                                        res = await e2e_worker.encrypt(args, clientPublicKey, projectName);
                                    } else res = args;
                                    emitable([res, not_encrypted]);
                                }]
                                : []
                        );
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

                const reqBuilder = ugly ? await e2e_worker.encrypt(mit, clientPublicKey, projectName) : null;

                const result = await (timeout ? socket.timeout(timeout) : socket)[promise ? 'emitWithAck' : 'emit'](
                    route,
                    [ugly ? reqBuilder : mit, not_encrypted],
                    ...hasEmitable
                        ? [async function () {
                            const [[args, not_encrypted]] = [...arguments];
                            let res;

                            if (ugly) {
                                res = (await e2e_worker.decrypt(args, projectName))[0];
                            } else res = args;

                            lastEmit(...discloseSocketArguments([res, not_encrypted]));
                        }]
                        : []
                );

                if (result && promise) {
                    return discloseSocketArguments([ugly ? (await e2e_worker.decrypt(result[0], projectName))[0] : result[0], result[1]])[0];
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
                }
            };

            Object.defineProperty(clonedSocket, 'disconnected', {
                get() {
                    return socket.disconnected;
                },
                enumerable: true,
                configurable: false
            });

            onSocketSnapshot(clonedSocket);
        } catch (e) {
            onSocketError?.(Object.assign(simplifyCaughtError(e).simpleError, { socket }));
        }
    });

    useSocketServer?.(io);

    server.listen(port, () => {
        console.log(`mosquito-transport server listening on port ${port}`);
    });

    return io;
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
    return args.map((obj, i) =>
        Object.entries(obj)
            .map(v => i ? [v[0] * 1, new DoNotEncrypt(v[1])] : v)
    ).flat()
        .sort((a, b) => a[0] - b[0]).map((v, i) => {
            if (v[0] !== i) throw 'corrupted socket arguments';
            return v[1];
        });
}