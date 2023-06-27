import express from "express";
import { niceTry, queryEntries, simplifyError } from "../../helpers/utils.js";
import { getDB } from "./base.js";
import _ from 'lodash';
import { validateJWT } from "../auth/tokenizer.js";
import { Scoped } from "../../helpers/variables.js";
import { handleSocketPlug } from "../../helpers/SocketHandler.js";
import { EngineRoutes } from "../../helpers/values.js";
import { DisconnectionWriteTaskListener } from "../../helpers/listeners.js";

export const TIMESTAMP = { $type: "timestamp" };

const {
    _listenCollection,
    _readDocument,
    _writeDocument,
    _queryCollection,
    _writeMapDocument,
    _listenDocument,
    _documentCount,
    _startDisconnectWriteTask,
    _cancelDisconnectWriteTask
} = EngineRoutes;

export const writeDocument = async ({ scope: scopeX, find, liveExist, value, path }, projectName, dbName, dbUrl) => {
    const scope = scopeX || 'setOne';

    // if (
    //     (scope === 'update' || scope === 'updateOne') &&
    //     !liveExist &&
    //     !(await readDocument({ path, find }, projectName, dbName, dbUrl))
    // ) throw simplifyError('document_not_found', 'You cannot update document that does not exist');

    const k = getDB(projectName, dbName, dbUrl).collection(path),
        deserializedValue = deserializeWriteValue(value),
        g = await (
            (scope === 'delete' || scope === 'deleteOne') ? k.deleteOne({ ...find })
                :
                scope === 'deleteMany' ? k.deleteMany({ ...find })
                    :
                    (scope === 'set' || scope === 'setOne') ? k.insertOne({ ...deserializedValue })
                        :
                        scope === 'setMany' ? k.insertMany(deserializedValue)
                            :
                            (scope === 'update' || scope === 'merge' || scope === 'updateOne' || scope === 'mergeOne')
                                ? k.updateOne({ ...find }, { ...deserializedValue }, { upsert: scope === 'merge' || scope === 'mergeOne' })
                                :
                                (scope === 'updateMany' || scope === 'mergeMany') ? k.updateMany({ ...find }, { ...deserializedValue }, { upsert: scope === 'merge' })
                                    :
                                    scope === 'replaceOne' ? k.replaceOne({ ...find }, { ...deserializedValue })
                                        :
                                        scope === 'putOne' ? k.replaceOne({ ...find }, { ...deserializedValue }, { upsert: true })
                                            :
                                            ({ fatalThrow: simplifyError('unknown_scope', `Invalid scope '${scope}'`) })
        );

    if (g.fatalThrow) throw g.fatalThrow;

    return g.acknowledged;
}

const deserializeWriteValue = (value) => {
    if (!value) return value;

    const tv = (Array.isArray(value) ? value : [value]).map(v => ({ ...v })),
        result = [...tv.map(() => ({}))],
        unset = [...tv.map(() => ({}))];

    tv.forEach((e, i) => {
        queryEntries(e).forEach(([key, value]) => {
            const l = key.split('.').filter((_, i, a) => i !== a.length - 1);

            if (key.endsWith('$timestamp') && value === 'now') {
                _.set(result[i], l.join('.'), Date.now());
            } else if (key.endsWith('$increment')) {
                _.set(result[i], l.map((v, i, a) => i === a.length - 1 ? `$inc.${v}` : v).join('.'), value || 1);
            } else if (key.endsWith('$deletion')) {
                _.set(unset[i], `${l.join('.')}`, value);
            } else _.set(result[i], key, value);
        });

        if (Object.keys(unset[i]).length) result[i]['$unset'] = unset[i];
    });

    return Array.isArray(value) ? result : result[0];
}

export const readDocument = async (commands, projectName, dbName, dbUrl) => {
    const d = await getDB(projectName, dbName, dbUrl).collection(commands.path || '').findOne({ ...commands.find });

    return await extractDocField(d, commands, projectName, dbName, dbUrl);
}

export const queryDocument = async (commands, projectName, dbName, dbUrl) => {
    const { path, limit, sort } = commands;
    let d = getDB(projectName, dbName, dbUrl).collection(path).find({ ...commands.find });

    if (sort) d = d.sort(sort);
    if (limit) d = d.limit(limit);

    d = await d.toArray();

    return Promise.all(d.map(v => extractDocField(v, commands, projectName, dbName, dbUrl)));
}

export const writeMapDocument = async (commands, projectName, dbName, dbUrl) => {
    const t = await Promise.all(
        commands.list.map(async v => {
            if (v.scope === 'update')
                return ({ ...v, liveExist: !!await readDocument({ path: v.path }, projectName, dbName, dbUrl) });
            return v;
        })
    ),
        updateNotFound = t.filter(v => v.scope === 'update' && !v.liveExist);

    if (updateNotFound.length)
        throw simplifyError('document_not_found', `You cannot update document that does not exist: ${updateNotFound.map(v => v.path).join(', ')}`);

    return await Promise.all(t.map(v => writeDocument(v, projectName, dbName, dbUrl)));
}

const extractDocField = async (d, commands, projectName, dbName, dbUrl) => {
    let finalData = d ? { ...d } : null;

    if (d) {
        commands.excludeFields?.forEach((e) => {
            if (finalData[e] && e !== '_id') delete finalData[e];
        });

        if (commands.returnOnly) {
            finalData = { _id: d._id };
            commands.returnOnly.forEach(e => {
                if (d[e]) finalData[e] = d[e];
            });
        }

        const foreignPromises = [],
            foreignDoc = Array.isArray(finalData._foreign_doc) ? finalData._foreign_doc : [finalData._foreign_doc],
            foreignList = Array.isArray(finalData._foreign_col) ? finalData._foreign_col : [finalData._foreign_col];

        if (finalData._foreign_doc) {
            foreignPromises.push(Promise.all(
                foreignDoc.map(v =>
                    getDB(projectName, dbName, dbUrl).collection(v.collection).findOne({ _id: v._id })
                )
            ));
        } else foreignPromises.push(Promise.resolve());

        if (finalData._foreign_col) {
            foreignPromises.push(Promise.all(
                foreignList.map(v =>
                    getDB(projectName, dbName, dbUrl).collection(v.collection).find({ ...v.find }).toArray()
                )
            ));
        } else foreignPromises.push(Promise.resolve());

        const foreignResolve = await Promise.all(foreignPromises);

        if (foreignResolve[0]) {
            const f = foreignDoc.map((v, i) => ({ _path: v, _data: foreignResolve[0][i] }));
            finalData._foreign_doc = Array.isArray(finalData._foreign_doc) ? f : f[0];
        }

        if (foreignResolve[1]) {
            const f = foreignList.map((v, i) => ({ _path: v, _data: foreignResolve[1][i] }));
            finalData._foreign_col = Array.isArray(finalData._foreign_col) ? f : f[0];
        }
    }

    return finalData;
}

export const emitDatabase = (path, callback, projectName, dbName, dbUrl, options) => {
    const { includeBeforeData, includeAfterData, pipeline } = options || {};

    const col = getDB(projectName, dbName, dbUrl).collection(path),
        stream = col.watch(pipeline, {
            fullDocument: includeAfterData ? 'required' : undefined,
            fullDocumentBeforeChange: includeBeforeData ? 'required' : undefined
        });

    stream.on('change', l => {
        const { operationType: ops, fullDocument, fullDocumentBeforeChange, documentKey, updateDescription, clusterTime } = l;

        if (ops !== 'insert' && ops !== 'delete' && ops !== 'update') return;
        callback?.({
            insertion: ops === 'insert' ? fullDocument : undefined,
            deletion: ops === 'delete' ? documentKey._id : undefined,
            update: ops === 'update' ? {
                ...updateDescription
            } : undefined,
            documentKey: documentKey._id,
            before: includeBeforeData ? fullDocumentBeforeChange : undefined,
            after: includeAfterData ? fullDocument : undefined,
            timestamp: clusterTime?.toNumber(),
            auth: undefined,
            operation: ops
        });
    });

    return () => {
        stream.close();
    }
}

export const databaseRoutes = ({ projectName, logger }) => [
    _readDocument,
    _writeDocument,
    _queryCollection,
    _writeMapDocument,
    _documentCount
].map(route =>
    express.Router({ caseSensitive: true }).post(`/${route}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('database'),
            now = Date.now();

        if (hasLogger) console.log(`started route: ${req.url}`);

        try {
            const { commands, dbName, dbUrl, authToken } = req.body,
                operation = route === '_readDocument' ? 'findOne' : route === '_queryCollection' ? 'findMany' : route === '_writeDocument' ? (commands.scope || 'setOne') : route === '_writeMapDocument' ? 'batchWrite' : 'unknown',
                auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : null;

            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                collection: commands.path || '',
                operation,
                find: commands.findOne || commands.find,
                value: commands.value,
                ...(operation === 'batchWrite' ? { batchWrite: commands.list } : {})
            };

            try {
                await Scoped.DatabaseRules[projectName]?.(rulesObj);
            } catch (e) {
                throw simplifyError('security_error', `${e}`);
            }

            switch (route) {
                case _readDocument:
                    const result = await readDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', result });
                    break;
                case _queryCollection:
                    const result1 = await queryDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', result: result1 });
                    break;
                case _writeDocument:
                    const committed = await writeDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', committed });
                    break;
                case _writeMapDocument:
                    const committed1 = await writeMapDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', committed: committed1 });
                    break;
                case _documentCount:
                    const counts = await getDB(projectName, dbName, dbUrl).collection(commands.path).countDocuments(commands.find || {});
                    res.status(200).send({ status: 'success', result: counts });
                    break;
            }
        } catch (e) {
            console.error(`errRoute: /${route} err:`, e);
            res.status(403).send({ status: 'error', ...(e.simpleError ? e : simplifyError('unexpected_error', `${e}`)) });
        }
        if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
    })
);

export const databaseLiveRoutes = ({ projectName, accessKey, logger }) => [
    _listenCollection,
    _listenDocument,
    _startDisconnectWriteTask,
    _cancelDisconnectWriteTask
].map(route =>
    handleSocketPlug(route, async (socket, _response, roof) => {
        const hasLogger = logger.includes('all') || logger.includes('database'),
            now = Date.now();

        if (hasLogger) console.log(`started route: /${route}`);

        const { mtoken, commands, dbName, dbUrl, accessKey: ak } = socket.handshake.auth,
            { path, find, findOne, scope } = commands,
            isDocumentWatch = route === _listenDocument,
            auth = mtoken ? await niceTry(() => validateJWT(mtoken, projectName)) : null;

        if (route === _listenDocument || route === _listenCollection) {
            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: mtoken } } : {}),
                collection: path,
                operation: isDocumentWatch ? 'listenDocument' : 'listenCollection',
                find: findOne || find
            };

            let emission, hasDisconnect, lastEmittedValue;

            try {
                if (accessKey !== ak) throw simplifyError('incorrect_access_key', 'The accessKey been provided is not correct');
                try {
                    await Scoped.DatabaseRules[projectName]?.(rulesObj);
                } catch (e) {
                    throw simplifyError('security_error', `${e}`);
                }

                const callSnapshot = async () => {
                    const a = await (isDocumentWatch ? readDocument : queryDocument)(commands, projectName, dbName, dbUrl);
                    if (hasDisconnect) return;
                    if (!_.isEqual(a, lastEmittedValue)) socket.emit('mSnapshot', [undefined, a]);
                    lastEmittedValue = a;
                }

                callSnapshot();
                emission = emitDatabase(path, () => {
                    callSnapshot();
                }, projectName, dbName, dbUrl, { pipeline: [{ $match: { ...(isDocumentWatch ? findOne : find) } }] })

            } catch (e) {
                console.error('listenDoc err:', e);
                socket.emit('mSnapshot', [(e?.simpleError ? e : simplifyError('unexpected_error', `${e}`)), undefined]);
            }

            socket.on('disconnect', () => {
                hasDisconnect = true;
                emission?.();
                if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
            });
        } else if (route === _startDisconnectWriteTask) {
            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: mtoken } } : {}),
                collection: path || '',
                operation: scope || 'setOne',
                find,
                value: commands.value,
                ...(scope === 'batchWrite' ? { batchWrite: commands.list } : {})
            };

            try {
                if (accessKey !== ak) throw simplifyError('incorrect_access_key', 'The accessKey been provided is not correct');
                try {
                    await Scoped.DatabaseRules[projectName]?.(rulesObj);
                } catch (e) {
                    throw simplifyError('security_error', `${e}`);
                }
                roof.writeTask = { commands, dbName, dbUrl };

                socket.on('disconnect', async () => {
                    if (roof.writeTask) {
                        const committed = await writeDocument(commands, projectName, dbName, dbUrl);
                        console.log('disconnectWriteTask: ', committed);
                        DisconnectionWriteTaskListener.triggerKeyListener(projectName, {
                            status: 'completed',
                            committed,
                            task: roof.writeTask
                        });
                        roof.writeTask = undefined;
                    }
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                });
            } catch (e) {
                DisconnectionWriteTaskListener.triggerKeyListener(projectName, {
                    status: 'error',
                    ...(e?.simpleError ? e : simplifyError('unexpected_error', `${e}`)),
                    task: { commands, dbName, dbUrl }
                });
                if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
            }
        } else if (route === _cancelDisconnectWriteTask) {
            DisconnectionWriteTaskListener.triggerKeyListener(projectName, { status: 'cancelled', task: roof.writeTask });
            roof.writeTask = undefined;
            socket.disconnect();
        }
    })
)