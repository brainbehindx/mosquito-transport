import express from "express";
import { niceTry, simplifyError } from "../../helpers/utils";
import { Scoped } from "../../helpers/variables";
import { validateJWT } from "../auth/tokenizer";
import fs from 'fs';
import { EngineRoutes, STORAGE_PATH, STORAGE_ROUTE } from "../../helpers/values";
import { mkdirp } from 'mkdirp';
import { StorageListener } from "../../helpers/listeners";
// import { dirname } from 'path';
// import { fileURLToPath } from 'url';
// const __dirname = dirname(fileURLToPath(import.meta.url));

const { _uploadFile, _deleteFile, _deleteFolder } = EngineRoutes;

export const storageRoutes = ({ projectName, externalAddress, logger }) => [
    _uploadFile,
    _deleteFile,
    _deleteFolder
].map(route =>
    express.Router({ caseSensitive: true })[route === _uploadFile ? 'post' : (route === _deleteFile || route === _deleteFolder) ? 'delete' : 'get'](`/${route}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('database'),
            now = Date.now();

        if (hasLogger) console.log(`started route: /${route}`);

        try {
            const { 'mosquitodb-token': authToken, 'mosquitodb-destination': destination, 'mosquitodb-encoding': encoding } = req.headers,
                { path } = req.body,
                auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : null;

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
            const systemDest = `${STORAGE_PATH(projectName)}/${path}`;

            switch (route) {
                case _uploadFile:
                    if (req.body !== undefined) {
                        const to = destination.trim(),
                            directory = `${STORAGE_PATH(projectName)}/${to}`,
                            tipDir = directory.split('/').filter((_, i, a) => i !== a.length - 1).join('/'),
                            downloadUrl = `${externalAddress}${STORAGE_ROUTE}/${to}`,
                            destErr = validateDestination(destination);

                        if (destErr) throw simplifyError('invalid_destination', destErr);
                        await mkdirp(tipDir);
                        let buf;

                        const sendEvent = () => {
                            StorageListener.dispatch(projectName, {
                                systemDest: directory,
                                dest: to,
                                buffer: buf,
                                operation: 'uploadFile',
                                auth: { ...auth, token: authToken }
                            });
                        }

                        if (encoding) {
                            buf = Buffer.from(req.body || '', encoding);

                            fs.writeFile(directory, buf, (err) => {
                                if (err) {
                                    res.status(403).send({ status: 'error', ...simplifyError('unexpected_error', `${err.message}`) });
                                } else {
                                    res.status(200).send({ status: 'success', downloadUrl });
                                    sendEvent();
                                }
                            });
                        } else {
                            const stream = fs.createWriteStream(directory, { autoClose: true });
                            buf = req.body;
                            req.pipe(stream);

                            stream.on('close', function () {
                                res.status(200).send({ status: 'success', downloadUrl });
                                sendEvent();
                            });
                            stream.on('error', function (err) {
                                res.status(403).send({ status: 'error', ...simplifyError('unexpected_error', `${err.message}`) });
                            });
                        }
                    } else throw simplifyError('no_file_provided');
                    break;
                case _deleteFile:
                    fs.unlink(systemDest, (err) => {
                        if (err) {
                            res.status(403).send({ status: 'error', ...simplifyError('failed', err.message) });
                        } else {
                            res.status(200).send({ status: 'success' });

                            StorageListener.dispatch(projectName, {
                                dest: path,
                                systemDest,
                                operation: 'deleteFile',
                                auth: { ...auth, token: authToken }
                            });
                        }
                    });
                    break;
                case _deleteFolder:
                    fs.rmdir(systemDest, { recursive: true, force: true }, (err) => {
                        if (err) {
                            res.status(403).send({ status: 'error', ...simplifyError('failed', err.message) });
                        } else {
                            res.status(200).send({ status: 'success' });

                            StorageListener.dispatch(projectName, {
                                dest: path,
                                systemDest,
                                operation: 'deleteFolder',
                                auth: { ...auth, token: authToken }
                            });
                        }
                    });
                    break;
            }
        } catch (e) {
            console.error(`errRoute: /${route} err:`, e);
            res.status(403).send({
                status: 'error',
                ...(e.simpleError ? e : simplifyError('unexpected_error', `${e}`))
            });
        }
        if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
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