import express from "express";
import { niceTry, simplifyError } from "../../helpers/utils";
import { Scoped } from "../../helpers/variables";
import { verifyJWT } from "../auth/tokenizer";
import fs from 'fs';
import { EngineRoutes, STORAGE_PATH, STORAGE_ROUTE } from "../../helpers/values";
import { mkdirp } from 'mkdirp';
// import { dirname } from 'path';
// import { fileURLToPath } from 'url';
// const __dirname = dirname(fileURLToPath(import.meta.url));

const { _uploadFile, _deleteFile, _deleteFolder } = EngineRoutes;

export const storageRoutes = ({ projectName, externalAddress }) => [
    _uploadFile,
    _deleteFile,
    _deleteFolder
].map(route =>
    express.Router({ caseSensitive: true })[route === _uploadFile ? 'post' : (route === _deleteFile || route === _deleteFolder) ? 'delete' : 'get'](`/${route}`, async (req, res) => {
        try {
            const { 'mosquitodb-token': authToken, 'mosquitodb-destination': destination, 'mosquitodb-encoding': encoding } = req.headers,
                { path } = req.body,
                auth = authToken ? await niceTry(() => verifyJWT(authToken, projectName)) : null;

            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                operation: route.substring(1),
                destination,
                path
            };

            try {
                await Scoped.StorageRules[projectName]?.(rulesObj);
            } catch (e) {
                throw simplifyError('security_error', `${e}`);
            }

            switch (route) {
                case _uploadFile:
                    if (!encoding || typeof req.body === 'string') {
                        const to = destination.trim(),
                            directory = `${STORAGE_PATH(projectName)}/${to}`,
                            tipDir = directory.split('/').filter((_, i, a) => i !== a.length - 1).join('/'),
                            downloadUrl = `${externalAddress}${STORAGE_ROUTE}/${to}`,
                            destErr = validateDestination(destination);

                        if (destErr) throw simplifyError('invalid_destination', e);
                        await mkdirp(tipDir);

                        if (encoding) {
                            fs.writeFile(directory, Buffer.from(req.body || '', encoding), (err) => {
                                if (err) {
                                    res.status(403).send({ status: 'error', ...simplifyError('unexpected_error', `${err.message}`) });
                                } else res.status(200).send({ status: 'success', downloadUrl });
                            });
                        } else {
                            const stream = fs.createWriteStream(directory, { autoClose: true });
                            req.pipe(stream);

                            stream.on('close', function () {
                                res.status(200).send({ status: 'success', downloadUrl });
                            });
                            stream.on('error', function (err) {
                                res.status(403).send({ status: 'error', ...simplifyError('unexpected_error', `${err.message}`) });
                            });
                        }
                    } else throw simplifyError('no_file_provided');
                    break;
                case _deleteFile:
                    fs.unlink(`${STORAGE_PATH(projectName)}/${path}`, (err) => {
                        if (err) {
                            res.status(403).send({ status: 'error', ...simplifyError('failed', err.message) });
                        } else res.status(200).send({ status: 'success' });
                    });
                    break;
                case _deleteFolder:
                    fs.rmdir(`${STORAGE_PATH(projectName)}/${path}`, { recursive: true, force: true }, (err) => {
                        if (err) {
                            res.status(403).send({ status: 'error', ...simplifyError('failed', err.message) });
                        } else res.status(200).send({ status: 'success' });
                    });
                    break;
            }
        } catch (e) {
            console.error('storageRoutes err:', e);
            res.status(403).send({ status: 'error', ...(e.simpleError ? e : simplifyError('unexpected_error', `${e}`)) });
        }
    })
);

const validateDestination = (t = '') => {
    t = t.trim();

    if (!t || typeof t !== 'string') return `destination is required`;
    if (t.startsWith('/') || t.endsWith('/')) return 'destination must neither start with "/" nor end with "/"';
    let l = '', r;

    t.split('').forEach(e => {
        if (e === '/' && l === '/') r = 'invalid destination path, "/" cannot be side by side';
        l = e;
    });

    return r;
};