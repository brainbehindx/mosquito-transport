import express from "express";
import EnginePath from "../../helpers/EnginePath.js";
import { handleSocketPlug } from "../../helpers/SocketHandler.js";
import { simplifyCaughtError, simplifyError } from "../../helpers/utils.js";
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

export const authRoutes = ({
    projectName,
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
].map(route =>
    express.Router({ caseSensitive: true }).post(`/${route}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('auth'),
            now = Date.now();

        if (hasLogger) console.log('started route: ', req.url);

        try {
            const { _, metadata: metax } = req.body;

            switch (route) {
                case _customSignup:
                    const [emailx, passwordx, namex] = _.split('</>').map(v => atob(v)),
                        aBuild = { email: emailx, password: passwordx, name: namex.trim(), request: req, metadata: metax, method: 'custom' },
                        { email = emailx, password = passwordx, name = namex, metadata = metax || {} } = sneakSignupAuth?.(aBuild) || aBuild,
                        result = await signupCustom(email, password, undefined, { email, name: name?.trim() || '' }, projectName, { metadata });

                    res.status(200).send({ status: 'success', result });
                    break;
                case _customSignin:
                    const [e, p] = _.split('</>').map(v => atob(v)),
                        r1 = await signinCustom(e, p, undefined, projectName);

                    res.status(200).send({ status: 'success', result: r1 });
                    break;
                case _signOut:
                    const r2 = await invalidateToken(_, projectName);
                    res.status(200).send({ status: 'success', result: r2 });
                    break;
                case _invalidateToken:
                    const r3 = await invalidateToken(_, projectName);
                    res.status(200).send({ status: 'success', result: r3 });
                    break;
                case _refreshAuthToken:
                    const r4 = await refreshToken(_, projectName);
                    res.status(200).send({ status: 'success', result: r4 });
                    break;
                case _googleSignin:
                    const r5 = await doGoogleSignin({ googleAuthConfig, token: _, mergeAuthAccount, projectName }, req, sneakSignupAuth, metax);

                    res.status(200).send({ status: 'success', result: r5 });
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
        if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
    })
);

export const authLiveRoutes = ({ projectName, logger }) => [
    _listenUserVerification,
].map(route =>
    handleSocketPlug(route, async (socket, _response) => {
        const hasLogger = logger.includes('all') || logger.includes('auth'),
            now = Date.now();

        if (hasLogger) console.log(`plug socket: /${route}`);
        if (route === _listenUserVerification) {
            const { mtoken } = socket.handshake.headers,
                { uid } = await validateJWT(mtoken, projectName),
                listener = listenUserVerificationState(verified => {
                    socket.emit('onVerificationChanged', [undefined, verified]);
                }, err => {
                    socket.emit('onVerificationChanged', [err]);
                    listener?.();
                }, uid, projectName);

            socket.on('disconnect', function () {
                listener?.();
                if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
            });
        }
    })
)

export const listenUserVerificationState = (callback, onError, uid, projectName) => {
    let hasEmit, emittion, lastEmailVerified, hasCancelled;

    readDocument({ path: EnginePath.userAcct, find: { _id: uid } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL).then(f => {
        if (!hasEmit) {
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

        if (verified !== lastEmailVerified) callback?.(verified);
        lastEmailVerified = verified;
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL, { pipeline: [{ $match: { _id: uid } }] });

    return () => {
        if (!hasCancelled) emittion();
        hasCancelled = true;
    }
}