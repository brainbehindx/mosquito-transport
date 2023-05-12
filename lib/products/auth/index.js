import express from "express";
import { invalidateToken, refreshToken, signinCustom, signupCustom } from "./customAuth";


export const authRoutes = (projectName) => [
    '_customSignin',
    '_customSignup',
    '_refreshAuthToken',
    '_googleSignin',
    '_appleSignin',
    '_facebookSignin',
    '_twitterSignin',
    '_githubSignin',
    '_signOut'
].map(route =>
    express.Router({ caseSensitive: true }).get(`/${route}`, async (req, res) => {
        try {
            const { _, extras, profile } = req.body;

            await authorizeRequest(req);
            switch (route) {
                case '_customSignup':
                    const [email, password] = _.split('</>').map(v => atob(v)),
                        result = await signupCustom(email, password, extras, undefined, profile, projectName);

                    res.status(200).send({ status: 'success', result });
                    break;
                case '_customSignin':
                    const [e, p] = _.split('</>').map(v => atob(v)),
                        r1 = await signinCustom(e, p, undefined, projectName);

                    res.status(200).send({ status: 'success', result: r1 });
                    break;
                case '_signOut':
                    const r2 = await invalidateToken(_, projectName);
                    res.status(200).send({ status: 'success', result: r2 });
                    break;
                case '_refreshAuthToken':
                    const r3 = await refreshToken(_, projectName);
                    res.status(200).send({ status: 'success', result: r3 });
                    break;
            }
        } catch (e) {
            res.status(403).send({ status: 'error', ...(e.simpleError ? e : simplifyError('unexpected_error', `${e}`)) });
        }
    })
);