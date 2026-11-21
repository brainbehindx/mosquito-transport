import express from "express";
import { encodeBinary } from "../../helpers/utils.js";
import { ADMIN_DB, EnginePath, EngineRoutes, ERRORS, NO_CACHE_HEADER, one_mb } from "../../helpers/values.js";
import { emitDatabase } from "../database/index.js";
import { invalidateToken, refreshToken, signinCustom, signupCustom, upgradeToken } from "./email_auth.js";
import { doGoogleSignin } from "./google_auth.js";
import { validateJWT } from "./tokenizer.js";
import { simplifyCaughtError } from 'simplify-error';
import { statusErrorCode, useDDOS } from "../../helpers/ddos.js";
import { serialize } from "entity-serializer";
import { doAppleSignin } from "./apple_auth.js";
import e2e_worker from "../../helpers/e2e_worker.js";
import { getDB } from "../database/base.js";

const {
    _listenUserVerification,
    _customSignin,
    _customSignup,
    _refreshAuthToken,
    _googleSignin,
    _appleSignin,
    _upgrade_auth_token,
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
    _appleSignin,
    // _facebookSignin,
    // _twitterSignin,
    // _githubSignin,
    _signOut
];

const AuthddosRouting = {
    [_customSignup]: 'signup',
    [_customSignin]: 'signin',
    [_signOut]: 'signout',
    [_refreshAuthToken]: 'refresh_token',
    [_upgrade_auth_token]: 'upgrade_token',
    [_googleSignin]: 'google_signin',
    [_appleSignin]: 'apple_signin'
};

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
    ipNode,
    onHandleTokenUpgrade
}) => {
    const hasLogger = logger.includes('all') || logger.includes('auth');
    const hasErrorLogger = logger.includes('all') || logger.includes('error');

    return [
        ...enforceE2E_Encryption ? [] : authRouteName.map(v => ({ mroute: v, route: v })),
        ...authRouteName.map(v => ({ mroute: `e2e/${encodeBinary(v)}`, route: v, ugly: true }))
    ].map(({ route, mroute, ugly }) => {

        return express.Router({ caseSensitive: true }).post(`/${mroute}`, async (req, res) => {
            const now = hasLogger && performance.now();

            if (hasLogger) console.log('started route: ', route);
            res.set(NO_CACHE_HEADER);

            try {
                if (
                    internals?.auth === false ||
                    (Array.isArray(internals?.auth) && !internals.auth.some(v => v === route))
                ) throw ERRORS.DISABLE_FEATURE;

                const ddosRouting = AuthddosRouting[route];

                useDDOS({
                    config: ddosMap,
                    requestPath: ddosRouting,
                    route: 'auth',
                    ipNode,
                    req
                });

                let reqBody, clientPublicKey;

                if (ugly) {
                    const [body, clientKey] = await e2e_worker.decrypt(req.body, projectName);
                    reqBody = body;
                    clientPublicKey = clientKey;
                } else reqBody = req.body;

                const { data, metadata: metax, token, r_token, platform } = reqBody;

                const makeResult = async (b) => {
                    return ugly ? serialize([await e2e_worker.encrypt(b, clientPublicKey, projectName)]) : b;
                }

                switch (route) {
                    case _customSignup:
                        const email = data.email.trim();
                        const name = name?.trim?.() || '';
                        const result = await signupCustom(email, data.password, undefined, { email, name }, projectName, { req, metadata: metax, name, platform });

                        res.status(200).send(await makeResult({ status: 'success', result }));
                        break;
                    case _customSignin:
                        const r1 = await signinCustom(data.email, data.password, undefined, projectName, undefined, { platform });
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
                    case _upgrade_auth_token:
                        if (!onHandleTokenUpgrade) throw `upgrading a token requires you to handle 'onHandleTokenUpgrade'`;

                        const user = await validateJWT(token, projectName);
                        const upgradeData = await onHandleTokenUpgrade({ input: data, user });
                        const upgradeDataSize = serialize(upgradeData).byteLength;

                        if (upgradeDataSize > one_mb)
                            throw `acr data must not exceed one megabytes but got size of ${upgradeDataSize} bytes`;

                        const upgradedResult = await upgradeToken(upgradeData, user, r_token, projectName);

                        res.status(200).send(
                            await makeResult({
                                status: 'success',
                                result: upgradedResult
                            })
                        );
                        break;
                    case _googleSignin:
                        const r5 = await doGoogleSignin({
                            googleAuthConfig,
                            token,
                            mergeAuthAccount,
                            projectName,
                            platform
                        }, req, interceptNewAuth, metax);

                        res.status(200).send(await makeResult({ status: 'success', result: r5 }));
                        break;
                    case _appleSignin:
                        const r6 = await doAppleSignin({
                            appleAuthConfig,
                            token,
                            mergeAuthAccount,
                            projectName,
                            platform
                        }, req, interceptNewAuth, metax);

                        res.status(200).send(await makeResult({ status: 'success', result: r6 }));
                        break;
                }
            } catch (e) {
                if (hasErrorLogger) console.error(`errRoute: /${route} err:`, e);
                const result = { status: 'error', ...simplifyCaughtError(e) };

                res.status(statusErrorCode(e)).send(ugly ? serialize([undefined, result]) : result);
            }
            if (hasLogger) console.log(`/${route} took: ${performance.now() - now}ms`);
        })
    });
}

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
}) => {
    const hasLogger = logger.includes('all') || logger.includes('auth');
    const logError = logger.includes('all') || logger.includes('error');
    const routeList = [
        ...enforceE2E_Encryption ? [] : authLivePath.map(v => ({ mroute: v, route: v })),
        ...authLivePath.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
    ];

    return (socket) => {
        const { auth: initAuthshake } = socket.handshake;
        const routeObj = routeList.find(v => v.mroute === initAuthshake._m_route);
        if (!routeObj) return;
        const { route, ugly } = routeObj;

        const now = hasLogger && performance.now();

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
                        const [body, clientKey] = await e2e_worker.decrypt(Buffer.from(initAuthshake.e2e, 'base64'), projectName);
                        mtoken = body.mtoken;
                        clientPublicKey = clientKey;
                    }
                    if (socket.disconnected) return;

                    let listener, hasDisconnected;
                    socket.on('disconnect', function () {
                        listener?.();
                        hasDisconnected = true;
                        if (hasLogger) console.log(`/${route} unplugged, live for ${performance.now() - now}ms`);
                    });

                    const { uid } = await validateJWT(mtoken, projectName);

                    if (hasDisconnected) return;
                    listener = listenUserVerificationState(async verified => {
                        try {
                            await validateJWT(mtoken, projectName);
                            socket.emit('onVerificationChanged', [
                                undefined,
                                ugly ? await e2e_worker.encrypt(!!verified, clientPublicKey, projectName) : !!verified
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
    };
}

export const listenUserVerificationState = (callback, onError, uid, projectName) => {
    let emittion, lastEmailVerified, hasCancelled, lastProcessID = 0;

    const dispatchEvent = async () => {
        const thisProcessID = ++lastProcessID;
        const data =
            await getDB(projectName, ADMIN_DB)
                .collection(EnginePath.userAcct)
                .findOne({ _id: uid });

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
    emittion =
        emitDatabase(EnginePath.userAcct, async s => {
            if (
                typeof s.update?.updatedFields?.passwordVerified === 'boolean' &&
                s.documentKey === uid
            ) {
                dispatchEvent();
            }
        }, projectName, undefined, ADMIN_DB);

    return () => {
        if (!hasCancelled) emittion();
        hasCancelled = true;
    }
};