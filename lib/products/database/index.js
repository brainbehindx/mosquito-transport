import express from "express";
import { IS_WHOLE_NUMBER, niceTry, queryEntries, simplifyError } from "../../helpers/utils.js";
import { getDB } from "./base.js";
import getLodash from 'lodash/get.js';
import setLodash from 'lodash/set.js';
import unsetLodash from 'lodash/unset.js';
import isEqual from "lodash/isEqual.js";
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
        const slash = queryEntries(e, undefined, undefined, '/'),
            dash = queryEntries(e, undefined, undefined, '-');

        slash.forEach(([key, value], x) => {
            const joints = key.split('').map((v, k) => (v === '/' && dash[x][0][k] === '-') ? k : null).filter(v => v !== null);

            const setValue = (inputValue) => {
                let lastSubIndex = 0, lastObj;

                if (joints.length) {
                    joints.forEach((d, x, a) => {
                        const s = key.substring(lastSubIndex, d);

                        if (!lastObj) {
                            if (!result[i][s]) result[i][s] = {};
                            lastObj = result[i][s];
                        } else {
                            if (!lastObj[s]) lastObj[s] = {};
                            lastObj = lastObj[s];
                        }
                        lastSubIndex = d + 1;

                        if (x === a.length - 1)
                            lastObj[key.substring(lastSubIndex)] = inputValue;
                    });
                } else result[i][key] = inputValue;
            }

            if (key.endsWith('/$timestamp') && value === 'now' && joints[joints.length - 1] === key.length - '/$timestamp'.length) {
                key = key.substring(0, key.length - '/$timestamp'.length);
                joints.pop();
                setValue(Date.now());
            } else setValue(value);
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
    const { path, limit, sort, random } = commands;
    let d = getDB(projectName, dbName, dbUrl).collection(path);

    if (random === true) {
        d = d.aggregate([{ $sample: { size: limit } }, { $match: { ...commands.find } }]);
    } else {
        d = d.find({ ...commands.find });
        if (sort) d = d.sort(sort);
        if (limit) d = d.limit(limit);
    }

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

export const assignExtractionFind = (data, find) => {
    const result = {};

    const sliceEntries = (findx, firstStage) => {
        return queryEntries(findx).map(([key, value]) => {
            const l = key.split('.').filter((_, i, a) => i !== a.length - 1);

            if (key.endsWith('$dynamicValue')) {
                if (typeof value !== 'string' || !value) throw '$dynamicValue must have a string value';
                const r = getLodash(data, value);
                return [l.join('.'), r];
            } else if (['$and', '$nor', '$or'].includes(key) && Array.isArray(value) && firstStage) {
                return [key, value.map(v => sliceEntries(v))]
            } else return [key, value];
        });
    }

    sliceEntries(find, true).forEach(([key, value]) => {
        setLodash(result, key, value);
    });

    return result;
}

const extractDocField = async (d, commands, projectName, dbName, dbUrl) => {
    let finalData = d ? { ...d } : null;

    if (d) {
        const { extraction, returnOnly, excludeFields } = commands.config || {};

        (Array.isArray(excludeFields) ? excludeFields : [excludeFields]).filter(v => v).forEach((e) => {
            if (getLodash(finalData, e) && e !== '_id') unsetLodash(finalData, e);
        });

        if (returnOnly) {
            finalData = { _id: d._id };
            (Array.isArray(returnOnly) ? returnOnly : [returnOnly]).filter(v => v).forEach(e => {
                if (getLodash(d, e)) setLodash(finalData, e, getLodash(d, e));
            });
        }

        const foreignDoc = Array.isArray(extraction) ? extraction : [extraction];

        if (extraction) {
            const extractedResult = await Promise.all(
                foreignDoc.map(v => async function () {
                    const t = { ...v },
                        { collection, direction, sort, limit, find, findOne } = t;
                    const ex = t.find ? 'collection' : 'document';

                    if (!collection) throw `Expected "collection" with string value in ${ex} extraction`;
                    if ((!find && !findOne) || (find && findOne)) throw `Expected one of "find" or "findOne" in ${ex} extraction`;
                    if (limit && (!IS_WHOLE_NUMBER(limit) || limit <= 0)) throw '"limit" must be a whole positive number in document extraction';
                    if (limit && findOne) throw '"limit" can only be done on a collection extraction';
                    if (sort && findOne) throw '"sort" can only be done on a collection extraction';
                    if (direction && findOne) throw '"direction" can only be done on a collection extraction';

                    const exFind = assignExtractionFind(d, find || findOne);

                    const { userAuth: { auth, authToken } } = commands,
                        operation = findOne ? 'findOne' : 'findMany';

                    const rulesObj = {
                        ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                        collection,
                        operation,
                        direction,
                        sort,
                        limit,
                        dbName,
                        dbUrl,
                        random: false,
                        find: exFind,
                        value: undefined
                    };

                    try {
                        await Scoped.DatabaseRules[projectName]?.(rulesObj);
                    } catch (e) {
                        throw simplifyError('security_error', `${e}`);
                    }

                    let colRef = getDB(projectName, dbName, dbUrl).collection(t.collection)[t.find ? 'find' : 'findOne'](exFind);

                    if (t.sort) colRef = colRef.sort(t.sort, t.direction);
                    if (t.limit) colRef = colRef.limit(t.limit);
                    if (t.find) colRef = colRef.toArray();

                    return colRef;
                }())
            );
            finalData._foreign_doc = Array.isArray(extraction) ? extractedResult : extractedResult[0];
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
                { scope, sort, direction, limit, random } = commands || {},
                operation = route === '_readDocument' ? 'findOne' : route === '_queryCollection' ? 'findMany' : route === '_writeDocument' ? (scope || 'setOne') : route === '_writeMapDocument' ? 'batchWrite' : 'unknown',
                auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : null;

            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                collection: commands.path || '',
                operation,
                direction,
                sort,
                limit,
                random: !!random,
                dbName,
                dbUrl,
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
                    const result = await readDocument({ ...commands, userAuth: { auth, authToken } }, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', result });
                    break;
                case _queryCollection:
                    const result1 = await queryDocument({ ...commands, userAuth: { auth, authToken } }, projectName, dbName, dbUrl);
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
            { path, find, findOne, scope, sort, direction, limit } = commands,
            isDocumentWatch = route === _listenDocument,
            auth = mtoken ? await niceTry(() => validateJWT(mtoken, projectName)) : null;

        if (route === _listenDocument || route === _listenCollection) {
            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: mtoken } } : {}),
                collection: path,
                direction,
                sort,
                limit,
                random: false,
                dbName,
                dbUrl,
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
                    const a = await (isDocumentWatch ? readDocument : queryDocument)({ ...commands, userAuth: { auth, authToken: mtoken } }, projectName, dbName, dbUrl);
                    if (hasDisconnect) return;
                    if (!isEqual(a, lastEmittedValue)) socket.emit('mSnapshot', [undefined, a]);
                    lastEmittedValue = a;
                }

                callSnapshot();
                emission = emitDatabase(path, () => {
                    callSnapshot();
                }, projectName, dbName, dbUrl, { pipeline: [{ $match: { ...(isDocumentWatch ? findOne : find) } }] })

            } catch (e) {
                if (hasLogger) console.error('listenDoc err:', e);
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
                dbName,
                dbUrl,
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
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                    if (roof.writeTask) {
                        const committed = await writeDocument(commands, projectName, dbName, dbUrl);
                        DisconnectionWriteTaskListener.dispatch(projectName, {
                            status: 'completed',
                            committed,
                            task: roof.writeTask
                        });
                        roof.writeTask = undefined;
                    }
                });
            } catch (e) {
                DisconnectionWriteTaskListener.dispatch(projectName, {
                    status: 'error',
                    ...(e?.simpleError ? e : simplifyError('unexpected_error', `${e}`)),
                    task: { commands, dbName, dbUrl }
                });
                if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
            }
        } else if (route === _cancelDisconnectWriteTask) {
            DisconnectionWriteTaskListener.dispatch(projectName, { status: 'cancelled', task: roof.writeTask });
            roof.writeTask = undefined;
            socket.disconnect();
        }
    })
)