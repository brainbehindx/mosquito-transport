import express from "express";

export const storageRoutes = (projectName) => [
    '_downloadFile',
    '_uploadFile',
    '_deleteFile'
].map(route =>
    express.Router({ caseSensitive: true })[route === '_uploadFile' ? 'post' : route === '_deleteFile' ? 'delete' : 'get'](`/${route}`, async (req, res) => {
        try {
            const { _, extras, profile } = req.body;

            await authorizeRequest(req);
            switch (route) {
                case '_downloadFile':
                    const [email, password] = _.split('</>').map(v => atob(v)),
                        result = await signupCustom(email, password, extras, undefined, profile);

                    res.status(200).send({ status: 'success', result });
                    break;
                case '_uploadFile':
                    const [e, p] = _.split('</>').map(v => atob(v)),
                        r1 = await signinCustom(e, p);

                    res.status(200).send({ status: 'success', result: r1 });
                    break;
                case '_deleteFile':
                    const r2 = await invalidateToken(_);
                    res.status(200).send({ status: 'success', result: r2 });
                    break;
            }
        } catch (e) {
            res.status(403).send({ status: 'error', ...(e.simpleError ? e : simplifyError('unexpected_error', `${e}`)) });
        }
    })
);