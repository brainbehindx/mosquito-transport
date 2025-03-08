import express from "express";
import { deserializeE2E, encodeBinary, niceTry, normalizeRoute, serializeE2E } from "../../helpers/utils";
import { Scoped } from "../../helpers/variables";
import { validateJWT } from "../auth/tokenizer";
import { EngineRoutes, ERRORS, NO_CACHE_HEADER, one_mb, STORAGE_DIRS, STORAGE_ROUTE } from "../../helpers/values";
import { StorageListener } from "../../helpers/listeners";
import { unlink } from "fs/promises";
import { simplifyCaughtError, simplifyError } from 'simplify-error';
import { deleteDir, deleteSource, streamWritableSource } from "./store";
import { join } from "path";
import { statusErrorCode, useDDOS } from "../../helpers/ddos";
import { serialize } from "entity-serializer";

const {
    _uploadFile,
    _deleteFile,
    _deleteFolder
} = EngineRoutes;

export const storageRouteName = [
    _uploadFile,
    _deleteFile,
    _deleteFolder
];

export const storageRoutes = ({
    projectName,
    externalAddress,
    logger,
    maxUploadBufferSize = one_mb * 1024,
    ddosMap,
    internals,
    enforceE2E_Encryption,
    ipNode
}) => [
    ...enforceE2E_Encryption ? [] : storageRouteName.map(v => ({ mroute: v, route: v })),
    ...storageRouteName.map(v => ({ mroute: `e2e/${encodeBinary(v)}`, route: v, ugly: true }))
].map(({ route, mroute, ugly }) =>
    express.Router({ caseSensitive: true })[
        {
            [_uploadFile]: 'post',
            [_deleteFile]: 'delete',
            [_deleteFolder]: 'delete'
        }[route] || 'get'
    ](`/${mroute}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('storage');
        const now = Date.now();

        if (hasLogger) console.log(`started route: /${route}`);
        res.set(NO_CACHE_HEADER);
        const shouldEncrypt = ugly && route !== _uploadFile;

        try {
            if (
                internals?.storage === false ||
                (Array.isArray(internals?.storage) && !internals.storage.some(v => v === route))
            ) throw ERRORS.DISABLE_FEATURE;

            const ddosRouting = {
                [_uploadFile]: 'upload',
                [_deleteFile]: 'delete',
                [_deleteFolder]: 'delete_folder'
            }[route];

            useDDOS(ddosMap, ddosRouting, 'storage', req, ipNode);

            const {
                'mosquito-token': authTokenx,
                'mosquito-destination': destination,
                'hash-upload': hash_upload
            } = req.headers;
            let authToken = authTokenx;
            let clientPublicKey, reqBody;

            if (shouldEncrypt) {
                const [body, clientKey, atoken] = await deserializeE2E(req.body, projectName);

                authToken = atoken;
                reqBody = body;
                clientPublicKey = clientKey;
            } else reqBody = req.body;

            const { path } = reqBody || {};
            const auth = authToken && validateJWT(authToken, projectName);

            const checkSecurity = async () => {
                const resolvedAuth = await auth;
                const rulesObj = {
                    headers: { ...req.headers },
                    ...resolvedAuth ? { auth: { ...resolvedAuth, token: authToken } } : {},
                    endpoint: route,
                    prescription: {
                        path: path || destination,
                        createHash: !!hash_upload
                    }
                };

                try {
                    await Scoped.InstancesData[projectName].storageRules?.(rulesObj);
                } catch (e) {
                    throw simplifyError('security_error', `${e}`);
                }
            };

            const makeResult = async (b) => {
                return shouldEncrypt ? serialize([await serializeE2E(b, clientPublicKey, projectName)]) : b;
            }

            switch (route) {
                case _uploadFile:
                    validateStoragePath(destination);

                    niceTry(() => removeVideoFreezer(destination, projectName));
                    await new Promise((resolve, reject) => {
                        const stream = streamWritableSource(
                            destination,
                            hash_upload === 'yes',
                            projectName,
                            async (err, uri) => {
                                const resolvedAuth = await auth;

                                if (err) reject(err);
                                else {
                                    resolve();
                                    StorageListener.dispatch(projectName, {
                                        uri,
                                        dest: normalizeRoute(destination),
                                        operation: 'uploadFile',
                                        ...resolvedAuth ? { auth: { ...resolvedAuth, token: authToken } } : {}
                                    });
                                }
                            }
                        );

                        let hasPassSecurity,
                            hasEndedStream,
                            byteReceived = 0,
                            tooBig;

                        req.on('data', buf => {
                            stream.write(buf);
                            if (byteReceived += buf.length > maxUploadBufferSize) {
                                tooBig = true;
                                reject(ERRORS.FILE_TOO_BIG(maxUploadBufferSize));
                            }
                        });

                        req.on('end', () => {
                            if (hasPassSecurity && !tooBig) stream.end();
                            hasEndedStream = true;
                        });

                        req.on('error', err => {
                            stream.destroy(err);
                        });

                        checkSecurity().then(() => {
                            hasPassSecurity = true;
                            if (hasEndedStream) stream.end();
                        }).catch(err => {
                            stream.destroy(err);
                        });
                    });

                    const linkAccess = new URL(externalAddress);
                    linkAccess.pathname = join(STORAGE_ROUTE, destination);

                    res.status(200).send({
                        status: 'success',
                        downloadUrl: linkAccess.href
                    });
                    break;
                case _deleteFile:
                    await checkSecurity();
                    const resolvedAuth = await auth;

                    validateStoragePath(path);
                    await deleteSource(path, projectName);
                    res.status(200).send(await makeResult({ status: 'success' }));
                    StorageListener.dispatch(projectName, {
                        dest: normalizeRoute(path),
                        operation: 'deleteFile',
                        ...resolvedAuth ? { auth: { ...resolvedAuth, token: authToken } } : {}
                    });
                    removeVideoFreezer(path, projectName);
                    break;
                case _deleteFolder:
                    await checkSecurity();
                    validateStoragePath(path);
                    await deleteDir(path, projectName);

                    const resolvedAuth1 = await auth;

                    StorageListener.dispatch(projectName, {
                        dest: normalizeRoute(path),
                        operation: 'deleteFolder',
                        ...resolvedAuth1 ? { auth: { ...resolvedAuth1, token: authToken } } : {}
                    });

                    res.status(200).send(await makeResult({ status: 'success' }));
                    removeVideoFreezer(path, projectName, true);
                    break;
            }
        } catch (e) {
            if (logger.includes('all') || logger.includes('error'))
                console.error(`errRoute: /${route} err:`, e);

            const result = { status: 'error', ...simplifyCaughtError(e) };
            res.status(statusErrorCode(e)).send(shouldEncrypt ? serialize([undefined, result]) : result);

            setTimeout(() => {
                req.destroy();
            }, 1000);
        }
        if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
    })
);

export const removeVideoFreezer = (path, projectName, isDir) => {
    const { VID_CACHER } = STORAGE_DIRS(projectName);
    const source = join(VID_CACHER, path);

    Object.entries(Scoped.cacheTranformVideoTimer).forEach(([k, v]) => {

        if (isDir ? v.inputFile.startsWith(source) : source === v.inputFile) {
            clearTimeout(v.timer);
            v.processList?.map?.(([_, reject]) => reject(new Error('file was updated in transit')));
            delete Scoped.cacheTranformVideoTimer[k];
            niceTry(() => unlink(k));
        }
    });
};

export const validateStoragePath = (t = '') => {
    if (typeof t !== 'string' || !t.trim()) throw 'path must be a non-empty string';
    if (t.startsWith(' ') || t.endsWith(' ')) throw 'path must be trimmed';
    if (t.startsWith('./') || t.startsWith('../')) throw 'path must be absolute';
    if (t.endsWith('/')) throw 'path must not end with "/"';
    if ('?'.split('').some(v => t.includes(v)))
        throw `path must not contain ?`;

    t = t.trim();
    let l = '';

    t.split('').forEach(e => {
        if (e === '/' && l === '/') throw 'invalid destination path, "/" cannot be duplicated side by side';
        l = e;
    });
};