import express from "express";
import EnginePath from "../../helpers/EnginePath.js";
import { handleSocketPlug } from "../../helpers/SocketHandler.js";
import { IS_RAW_OBJECT, decryptString, encryptString, niceTry, simplifyCaughtError, simplifyError } from "../../helpers/utils.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, EngineRoutes } from "../../helpers/values.js";
import { emitDatabase, readDocument } from "../database/index.js";
import { invalidateToken, refreshToken, signinCustom, signupCustom } from "./customAuth.js";
import { doGoogleSignin } from "./googleAuth.js";
import { validateJWT, verifyJWT } from "./tokenizer.js";
import Base64_PKG from 'base-64';
const { encode: btoa } = Base64_PKG;

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

const dbRoute = [
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
    fallbackAuthConfig
}) => [
    ...dbRoute.map(v => ({ mroute: v, route: v })),
    ...dbRoute.map(v => ({ mroute: btoa(v), route: v, ugly: true }))
].map(({ route, mroute, ugly }) =>
    express.Router({ caseSensitive: true }).post(`/${mroute}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('auth'),
            now = Date.now();

        if (hasLogger) console.log('started route: ', route);

        try {
            const { 'mosquitodb-token': authToken, authorization } = req.headers,
                [auth, nauth] = authToken ? await Promise.all([
                    niceTry(() => validateJWT(authToken, projectName)),
                    niceTry(() => verifyJWT(authToken, projectName))
                ]) : [];

            if (decryptString((authorization || '').split(' ')[1] || '', accessKey, '_') !== accessKey)
                throw simplifyError('incorrect_access_key', 'The accessKey been provided is not correct');

            let reqBody;

            if (ugly) {
                if (authToken && !nauth)
                    throw simplifyError('invalid_auth_token', 'token provided is invalid');
                reqBody = decryptString(req.body.__, accessKey, authToken ? nauth?.encryptionKey : accessKey);
                if (!reqBody) throw simplifyError('decryption_failed', 'Decrypting request body failed');
                reqBody = JSON.parse(reqBody);
            } else reqBody = req.body;

            const { _, metadata: metax } = reqBody;

            const makeResult = (res) => {
                return ugly ? { __: encryptString(JSON.stringify(res), accessKey, authToken ? nauth.encryptionKey : accessKey) } : res;
            }

            switch (route) {
                case _customSignup:
                    const [emailx, passwordx, namex] = _.split('</>').map(v => atob(v)),
                        aBuild = { email: emailx, password: passwordx, name: namex.trim(), request: req, metadata: metax, method: 'custom' },
                        { email, password, name } = aBuild,
                        sneakData = sneakSignupAuth?.(aBuild),
                        result = await signupCustom(email, password, undefined, { email, name: name?.trim() || '' }, projectName, {
                            metadata: {
                                ...metax,
                                ...(IS_RAW_OBJECT(sneakData) ? sneakData : {})
                            }
                        });

                    res.status(200).send(makeResult({ status: 'success', result }));
                    break;
                case _customSignin:
                    const [e, p] = _.split('</>').map(v => atob(v)),
                        r1 = await signinCustom(e, p, undefined, projectName);

                    res.status(200).send(makeResult({ status: 'success', result: r1 }));
                    break;
                case _signOut:
                    const r2 = await invalidateToken(_, projectName);
                    res.status(200).send(makeResult({ status: 'success', result: r2 }));
                    break;
                case _invalidateToken:
                    const r3 = await invalidateToken(_, projectName);
                    res.status(200).send(makeResult({ status: 'success', result: r3 }));
                    break;
                case _refreshAuthToken:
                    const r4 = await refreshToken(_, projectName);
                    res.status(200).send(makeResult({ status: 'success', result: r4 }));
                    break;
                case _googleSignin:
                    const r5 = await doGoogleSignin({ googleAuthConfig, token: _, mergeAuthAccount, projectName }, req, sneakSignupAuth, metax);

                    res.status(200).send(makeResult({ status: 'success', result: r5 }));
                    break;
                case _appleSignin:
                    throw '';
                    const r6 = await doGoogleSignin({ googleAuthConfig, token: _, mergeAuthAccount, projectName });

                    res.status(200).send({ status: 'success', result: r5 });
                    break;
            }
        } catch (e) {
            if (hasLogger) console.error(`errRoute: /${route} err:`, e);
            res.status(403).send({ status: 'error', ...simplifyCaughtError(e) });
        }
        if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
    })
);

export const authLiveRoutes = ({ projectName, logger }) => [
    _listenUserVerification,
].map(route =>
    handleSocketPlug(route, async (socket) => {
        const hasLogger = logger.includes('all') || logger.includes('auth'),
            now = Date.now();

        if (hasLogger) console.log(`plug socket: /${route}`);
        if (route === _listenUserVerification) {
            try {
                const { mtoken } = socket.handshake.auth,
                    { uid } = await validateJWT(mtoken, projectName);

                const listener = listenUserVerificationState(async verified => {
                    try {
                        await validateJWT(mtoken, projectName);
                        socket.emit('onVerificationChanged', [undefined, verified]);
                    } catch (e) {
                        socket.emit('onVerificationChanged', [simplifyCaughtError(e)]);
                    }
                }, err => {
                    socket.emit('onVerificationChanged', [simplifyCaughtError(err)]);
                }, uid, projectName);

                socket.on('disconnect', function () {
                    listener?.();
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                });
            } catch (e) {
                socket.emit('onVerificationChanged', [simplifyCaughtError(e)]);
            }
        }
    })
)

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
        const verified = Object.keys(s.update || {}).includes('emailVerified') ? s.update?.updatedFields?.emailVerified : lastEmailVerified;

        if (verified !== lastEmailVerified && typeof verified === 'boolean') callback?.(verified);
        lastEmailVerified = verified;
        hasEmit = true;
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL, { pipeline: [{ $match: { _id: uid } }] });

    return () => {
        if (!hasCancelled) emittion();
        hasCancelled = true;
    }
}