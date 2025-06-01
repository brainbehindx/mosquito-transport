import express from "express";
import { decodeBinary, deserializeE2E, encodeBinary, serializeE2E } from "../../helpers/utils.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, EnginePath, EngineRoutes, ERRORS, NO_CACHE_HEADER } from "../../helpers/values.js";
import { emitDatabase, readDocument } from "../database/index.js";
import { invalidateToken, refreshToken, signinCustom, signupCustom } from "./email_auth.js";
import { doGoogleSignin } from "./google_auth.js";
import { validateJWT } from "./tokenizer.js";
import { Validator } from "guard-object";
import { simplifyCaughtError } from 'simplify-error';
import { statusErrorCode, useDDOS } from "../../helpers/ddos.js";
import { serialize } from "entity-serializer";

const {
    _listenUserVerification,
    _customSignin,
    _customSignup,
    _refreshAuthToken,
    _googleSignin,
    _appleSignin,
    _facebookSignin,
    _twitterSignin,
    _githubSignin,
    _signOut
} = EngineRoutes;

export const authRouteName = [
    _customSignin,
    _customSignup,
    _refreshAuthToken,
    _googleSignin,
    // _appleSignin,
    // _facebookSignin,
    // _twitterSignin,
    // _githubSignin,
    // _appleSignin,
    _signOut
];

export const authRoutes = ({
    projectName,
    logger,
    mergeAuthAccount = true,
    interceptNewAuth,
    googleAuthConfig,
    appleAuthConfig,
    facebookAuthConfig,
    githubAuthConfig,
    twitterAuthConfig,
    fallbackAuthConfig,
    enforceE2E_Encryption,
    ddosMap,
    internals,
    ipNode
}) => [
    ...enforceE2E_Encryption ? [] : authRouteName.map(v => ({ mroute: v, route: v })),
    ...authRouteName.map(v => ({ mroute: `e2e/${encodeBinary(v)}`, route: v, ugly: true }))
].map(({ route, mroute, ugly }) =>
    express.Router({ caseSensitive: true }).post(`/${mroute}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('auth'),
            now = hasLogger && Date.now();

        if (hasLogger) console.log('started route: ', route);
        res.set(NO_CACHE_HEADER);

        try {
            if (
                internals?.auth === false ||
                (Array.isArray(internals?.auth) && !internals.auth.some(v => v === route))
            ) throw ERRORS.DISABLE_FEATURE;

            const ddosRouting = {
                [_customSignup]: 'signup',
                [_customSignin]: 'signin',
                [_signOut]: 'signout',
                [_refreshAuthToken]: 'refresh_token',
                [_googleSignin]: 'google_signin'
            }[route];

            useDDOS(ddosMap, ddosRouting, 'auth', req, ipNode);

            let reqBody, clientPublicKey;

            if (ugly) {
                const [body, clientKey] = await deserializeE2E(req.body, projectName);
                reqBody = body;
                clientPublicKey = clientKey;
            } else reqBody = req.body;

            const { data, metadata: metax, token, r_token } = reqBody;

            const makeResult = async (b) => {
                return ugly ? serialize([await serializeE2E(b, clientPublicKey, projectName)]) : b;
            }

            switch (route) {
                case _customSignup:
                    const [emailx, passwordx, namex = ''] = data.split('.').map(v => decodeBinary(v));
                    const aBuild = {
                        email: emailx,
                        password: passwordx,
                        name: namex.trim(),
                        request: req,
                        metadata: metax,
                        method: AUTH_PROVIDER_ID.PASSWORD
                    };
                    const { email, password, name } = aBuild;
                    const { metadata = metax || {}, profile, uid: d_uid } = (await interceptNewAuth?.(aBuild)) || {};
                    const result = await signupCustom(email, password, undefined, { email, name: name.trim() || '' }, projectName, {
                        metadata: {
                            ...Validator.OBJECT(metadata) ? metadata : {}
                        },
                        profile: {
                            ...Validator.OBJECT(profile) ? profile : {}
                        },
                        d_uid
                    });

                    res.status(200).send(await makeResult({ status: 'success', result }));
                    break;
                case _customSignin:
                    const [e, p] = data.split('.').map(v => decodeBinary(v)),
                        r1 = await signinCustom(e, p, undefined, projectName);

                    res.status(200).send(await makeResult({ status: 'success', result: r1 }));
                    break;
                case _signOut:
                    const r2 = await Promise.all([
                        invalidateToken(token, projectName),
                        invalidateToken(r_token, projectName, true),
                    ]);
                    res.status(200).send(await makeResult({ status: 'success', result: r2 }));
                    break;
                case _refreshAuthToken:
                    const r4 = await refreshToken({ token, refToken: r_token }, projectName);
                    res.status(200).send(await makeResult({ status: 'success', result: r4 }));
                    break;
                case _googleSignin:
                    const r5 = await doGoogleSignin({
                        googleAuthConfig,
                        token,
                        mergeAuthAccount,
                        projectName
                    }, req, interceptNewAuth, metax);

                    res.status(200).send(await makeResult({ status: 'success', result: r5 }));
                    break;
                case _appleSignin:
                    throw '';
                    // const r6 = await doGoogleSignin({ googleAuthConfig, token: _, mergeAuthAccount, projectName });

                    // res.status(200).send({ status: 'success', result: r5 });
                    break;
            }
        } catch (e) {
            if (
                logger.includes('all') ||
                logger.includes('error')
            ) console.error(`errRoute: /${route} err:`, e);
            const result = { status: 'error', ...simplifyCaughtError(e) };

            res.status(statusErrorCode(e)).send(ugly ? serialize([undefined, result]) : result);
        }
        if (hasLogger) console.log(`/${route} took: ${Date.now() - now}ms`);
    })
);

export const authLivePath = [
    _listenUserVerification
];

/**
 * @type {(config: any) => (socket: import('socket.io').Socket)=> void}
 */
export const authLiveRoutesHandler = ({
    projectName,
    logger,
    enforceE2E_Encryption,
    internals
}) => (socket) => {
    const { auth: initAuthshake } = socket.handshake;
    const routeList = [
        ...enforceE2E_Encryption ? [] : authLivePath.map(v => ({ mroute: v, route: v })),
        ...authLivePath.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
    ];
    const routeObj = routeList.find(v => v.mroute === initAuthshake._m_route);
    if (!routeObj) return;
    const { route, ugly } = routeObj;

    const hasLogger = logger.includes('all') || logger.includes('auth');
    const logError = logger.includes('all') || logger.includes('error');
    const now = Date.now();

    if (hasLogger) console.log(`plugged socket: /${route}`);
    (async () => {
        if (route === _listenUserVerification) {
            try {
                if (
                    internals?.auth === false ||
                    (Array.isArray(internals?.auth) && !internals.auth.some(v => v === route))
                ) throw ERRORS.DISABLE_FEATURE;

                let mtoken = initAuthshake.mtoken,
                    clientPublicKey;

                if (ugly) {
                    const [body, clientKey] = await deserializeE2E(Buffer.from(initAuthshake.e2e, 'base64'), projectName);
                    mtoken = body.mtoken;
                    clientPublicKey = clientKey;
                }
                if (socket.disconnected) return;

                let listener, hasDisconnected;
                socket.on('disconnect', function () {
                    listener?.();
                    hasDisconnected = true;
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                });

                const { uid } = await validateJWT(mtoken, projectName);

                if (hasDisconnected) return;
                listener = listenUserVerificationState(async verified => {
                    try {
                        await validateJWT(mtoken, projectName);
                        socket.emit('onVerificationChanged', [
                            undefined,
                            ugly ? await serializeE2E(!!verified, clientPublicKey, projectName) : !!verified
                        ]);
                    } catch (e) {
                        socket.emit('onVerificationChanged', [simplifyCaughtError(e)]);
                    }
                }, err => {
                    if (logError) console.error(`/${route} err: `, err);
                    socket.emit('onVerificationChanged', [simplifyCaughtError(err)]);
                }, uid, projectName);
            } catch (e) {
                if (logError) console.error(`errRoute: /${route} err: `, e);
                socket.emit('onVerificationChanged', [simplifyCaughtError(e)]);
            }
        }
    })();
}

export const listenUserVerificationState = (callback, onError, uid, projectName) => {
    let emittion, lastEmailVerified, hasCancelled, lastProcessID = 0;

    const dispatchEvent = async () => {
        const thisProcessID = ++lastProcessID;
        const data = await readDocument({
            path: EnginePath.userAcct,
            find: { _id: uid }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        const thisVerified = data?.passwordVerified;

        if (
            !hasCancelled &&
            thisProcessID === lastProcessID &&
            thisVerified !== lastEmailVerified
        ) {
            if (data) {
                callback?.(!!thisVerified);
            } else onError?.(ERRORS.TOKEN_USER_NOT_FOUND);
            lastEmailVerified = thisVerified;
        }
    }

    dispatchEvent();
    emittion = emitDatabase(EnginePath.userAcct, async s => {
        if (
            typeof s.update?.updatedFields?.passwordVerified === 'boolean' &&
            s.documentKey === uid
        ) {
            dispatchEvent();
        }
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

    return () => {
        if (!hasCancelled) emittion();
        hasCancelled = true;
    }
};