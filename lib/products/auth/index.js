import express from "express";
import EnginePath from "../../helpers/EnginePath.js";
import { handleSocketPlug } from "../../helpers/SocketHandler.js";
import { simplifyError } from "../../helpers/utils.js";
import { EngineRoutes } from "../../helpers/values.js";
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
    mergeAuthAccount = true,
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
        try {
            const { _, metadata } = req.body;

            switch (route) {
                case _customSignup:
                    const [email, password, name] = _.split('</>').map(v => atob(v)),
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
                    const r5 = await doGoogleSignin({ googleAuthConfig, token: _, mergeAuthAccount, projectName });

                    res.status(200).send({ status: 'success', result: r5 });
                    break;
            }
        } catch (e) {
            console.error('authRoutes err:', e);
            res.status(403).send({ status: 'error', ...(e?.simpleError ? e : simplifyError('unexpected_error', `${e}`)) });
        }
    })
);

export const authLiveRoutes = ({ projectName }) => [
    _listenUserVerification,
].map(route =>
    handleSocketPlug(route, async (socket, response) => {
        if (route === _listenUserVerification) {

            const { mtoken } = socket.handshake.headers,
                { uid } = await validateJWT(mtoken, projectName),
                listener = listenUserVerificationState(verified => {
                    socket.emit('onVerificationChanged', [undefined, verified]);
                }, err => {
                    socket.emit('onVerificationChanged', [err]);
                    listener?.();
                }, uid);

            socket.on('disconnect', function () {
                listener?.();
            });
        }
    })
)

export const listenUserVerificationState = (callback, onError, uid) => {
    let hasEmit, emittion, lastEmailVerified, hasCancelled;

    readDocument({ path: EnginePath.userAcct(), find: { _id: uid } }).then(f => {
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

    emittion = emitDatabase(EnginePath.userAcct(), async s => {
        if (s.deletion) {
            onError?.(simplifyError('user_not_found', 'This user was not found on our database'));
            emittion();
            hasCancelled = true;
            return;
        }
        const verified = Object.keys(s.update || {}).includes('emailVerified') ? s.update?.updatedFields?.emailVerified : lastEmailVerified;

        if (verified !== lastEmailVerified) callback?.(verified);
        lastEmailVerified = verified;
    }, { pipeline: [{ $match: { _id: uid } }] });

    return () => {
        if (!hasCancelled) emittion();
        hasCancelled = true;
    }
}