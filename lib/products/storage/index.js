import express from "express";
import { niceTry } from "../../helpers/utils";
import { Scoped } from "../../helpers/variables";
import { verifyJWT } from "../auth/tokenizer";

export const storageRoutes = (projectName) => [
    '_downloadFile',
    '_uploadFile',
    '_deleteFile'
].map(route =>
    express.Router({ caseSensitive: true })[route === '_uploadFile' ? 'post' : route === '_deleteFile' ? 'delete' : 'get'](`/${route}`, async (req, res) => {
        try {
            const { authToken, destination } = {} || req.body,
                auth = authToken ? await niceTry(() => verifyJWT(authToken, projectName)) : null;

            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                operation: route.substring(1),
                destination
            };

            try {
                await Scoped.StorageRules[projectName]?.(rulesObj);
            } catch (e) {
                throw simplifyError('security_error', `${e}`);
            }

            await authorizeRequest(req);
            switch (route) {
                case '_downloadFile':
                    res.status(200).send({ status: 'success' });
                    break;
                case '_uploadFile':
                    console.log('files result: ', req.files.foo);
                    res.status(200).send({ status: 'success' });
                    break;
                case '_deleteFile':
                    res.status(200).send({ status: 'success' });
                    break;
            }
        } catch (e) {
            res.status(403).send({ status: 'error', ...(e.simpleError ? e : simplifyError('unexpected_error', `${e}`)) });
        }
    })
);

const handleUploadedFile = () => {

}