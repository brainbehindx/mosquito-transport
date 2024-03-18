import express from "express";
import EnginePath from "../../helpers/EnginePath.js";
import { handleSocketPlug } from "../../helpers/SocketHandler.js";
import { IS_RAW_OBJECT, decodeBinary, deserializeE2E, encodeBinary, serializeE2E, simplifyCaughtError, simplifyError } from "../../helpers/utils.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, EngineRoutes } from "../../helpers/values.js";
import { emitDatabase, readDocument } from "../database/index.js";
import { invalidateToken, refreshToken, signinCustom, signupCustom } from "./customAuth.js";
import { doGoogleSignin } from "./googleAuth.js";
import { validateJWT } from "./tokenizer.js";

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
    _signOut,
    _invalidateToken
} = EngineRoutes;

const authRoute = [
    _customSignin,
    _customSignup,
    _refreshAuthToken,
    _googleSignin,
    // _appleSignin,
    // _facebookSignin,
    // _twitterSignin,
    // _githubSignin,
    // _appleSignin,
    _signOut,
    _invalidateToken
];

export const authRoutes = ({
    projectName,
    accessKey,
    logger,
    mergeAuthAccount = true,
    sneakSignupAuth,
    googleAuthConfig,
    appleAuthConfig,
    facebookAuthConfig,
    githubAuthConfig,
    twitterAuthConfig,
    fallbackAuthConfig,
    enforceETE_Encryption
}) => [
    ...(enforceETE_Encryption ? [] : authRoute.map(v => ({ mroute: v, route: v }))),
    ...authRoute.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
].map(({ route, mroute, ugly }) =>
    express.Router({ caseSensitive: true }).post(`/${mroute}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('auth'),
            now = Date.now();

        if (hasLogger) console.log('started route: ', route);

        try {
            const { authorization } = req.headers;
            if (authorization !== accessKey)
                throw simplifyError('incorrect_access_key', 'The accessKey been provided is not correct');

            let reqBody, clientPublicKey;

            if (ugly) {
                const [body, clientKey] = deserializeE2E(req.body, projectName);
                reqBody = body;
                clientPublicKey = clientKey;
            } else reqBody = req.body;

            const { _, metadata: metax, token, r_token } = reqBody;

            const makeResult = (b) => {
                return ugly ? { e2e: serializeE2E(b, clientPublicKey, projectName) } : b;
            }

            switch (route) {
                case _customSignup:
                    const [emailx, passwordx, namex = ''] = _.split('.').map(v => decodeBinary(v)),
                        aBuild = {
                            email: emailx,
                            password: passwordx,
                            name: namex.trim(),
                            request: req,
                            metadata: metax,
                            method: 'custom'
                        },
                        { email, password, name } = aBuild,
                        { metadata = metax || {}, profile, uid: d_uid } = sneakSignupAuth?.(aBuild),
                        result = await signupCustom(email, password, undefined, { email, name: name.trim() || '' }, projectName, {
                            metadata: {
                                ...(IS_RAW_OBJECT(metadata) ? metadata : {})
                            },
                            profile: {
                                ...(IS_RAW_OBJECT(profile) ? profile : {})
                            },
                            d_uid
                        });

                    res.status(200).send(makeResult({ status: 'success', result }));
                    break;
                case _customSignin:
                    const [e, p] = _.split('.').map(v => decodeBinary(v)),
                        r1 = await signinCustom(e, p, undefined, projectName);

                    res.status(200).send(makeResult({ status: 'success', result: r1 }));
                    break;
                case _signOut:
                    const r2 = await Promise.all([
                        invalidateToken(token, projectName),
                        invalidateToken(r_token, projectName, true),
                    ]);
                    res.status(200).send(makeResult({ status: 'success', result: r2 }));
                    break;
                case _invalidateToken:
                    const r3 = await invalidateToken(token, projectName);
                    res.status(200).send(makeResult({ status: 'success', result: r3 }));
                    break;
                case _refreshAuthToken:
                    const r4 = await refreshToken({ token, refToken: r_token }, projectName);
                    res.status(200).send(makeResult({ status: 'success', result: r4 }));
                    break;
                case _googleSignin:
                    const r5 = await doGoogleSignin({
                        googleAuthConfig,
                        token,
                        mergeAuthAccount,
                        projectName
                    }, req, sneakSignupAuth, metax);

                    res.status(200).send(makeResult({ status: 'success', result: r5 }));
                    break;
                case _appleSignin:
                    throw '';
                    // const r6 = await doGoogleSignin({ googleAuthConfig, token: _, mergeAuthAccount, projectName });

                    // res.status(200).send({ status: 'success', result: r5 });
                    break;
            }
        } catch (e) {
            if (hasLogger) console.error(`errRoute: /${route} err:`, e);
            res.status(403).send({ status: 'error', ...simplifyCaughtError(e) });
        }
        if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
    })
);

export const authLivePath = [
    _listenUserVerification
];

export const authLiveRoutes = ({ projectName, logger, enforceETE_Encryption }) => [
    ...(enforceETE_Encryption ? [] : authLivePath.map(v => ({ mroute: v, route: v }))),
    ...authLivePath.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
].map(({ route, mroute, ugly }) =>
    handleSocketPlug(mroute, async (socket) => {
        const hasLogger = logger.includes('all') || logger.includes('auth'),
            now = Date.now();

        if (hasLogger) console.log(`plug socket: /${route}`);
        if (route === _listenUserVerification) {
            try {
                const initAuthHandshake = socket.handshake.auth;
                let mtoken = initAuthHandshake.mtoken, clientPublicKey;

                if (ugly) {
                    const [body, clientKey] = deserializeE2E(initAuthHandshake.e2e, projectName);
                    mtoken = body.mtoken;
                    clientPublicKey = clientKey;
                }

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
                            serializeE2E(!!verified, clientPublicKey, projectName)
                        ]);
                    } catch (e) {
                        socket.emit('onVerificationChanged', [simplifyCaughtError(e)]);
                    }
                }, err => {
                    socket.emit('onVerificationChanged', [simplifyCaughtError(err)]);
                }, uid, projectName);
            } catch (e) {
                socket.emit('onVerificationChanged', [simplifyCaughtError(e)]);
            }
        }
    })
);

export const listenUserVerificationState = (callback, onError, uid, projectName) => {
    let hasEmit, emittion, lastEmailVerified, hasCancelled;

    readDocument({ path: EnginePath.userAcct, find: { _id: uid } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL).then(f => {
        if (!hasEmit && !hasCancelled) {
            if (!f) {
                onError?.(simplifyError('user_not_found', 'This user was not found on our database'));
                emittion();
                hasCancelled = true;
                return;
            }
            lastEmailVerified = f.emailVerified;
            callback?.(f.emailVerified);
        }
    });

    emittion = emitDatabase(EnginePath.userAcct, async s => {
        if (s.deletion) {
            onError?.(simplifyError('user_not_found', 'This user was not found on our database'));
            emittion();
            hasCancelled = true;
            return;
        }
        const verified = s.update?.updatedFields?.emailVerified;

        if (typeof verified === 'boolean') {
            if (verified !== lastEmailVerified) callback?.(verified);
            lastEmailVerified = verified;
            hasEmit = true;
        }
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL, { pipeline: { _id: uid } });

    return () => {
        if (!hasCancelled) emittion();
        hasCancelled = true;
    }
}