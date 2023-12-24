import express from "express";
import { IS_WHOLE_NUMBER, deserializeE2E, niceTry, queryEntries, serializeE2E, simplifyCaughtError, simplifyError } from "../../helpers/utils.js";
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
import Base64_PKG from 'base-64';
const { encode: btoa } = Base64_PKG;

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

export const writeDocument = async ({ scope: scopeX, find, value, path }, projectName, dbName, dbUrl) => {
    const scope = scopeX || 'setOne';

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
                                ? k.updateOne({ ...find }, { ...deserializedValue }, {
                                    upsert: scope === 'merge' || scope === 'mergeOne'
                                })
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
    const { path, limit, sort, direction, random } = commands;
    let d = getDB(projectName, dbName, dbUrl).collection(path);

    if (random === true) {
        d = d.aggregate([{ $sample: { size: limit } }, { $match: { ...commands.find } }]);
    } else {
        d = d.find({ ...commands.find });
        if (sort) d = d.sort(sort, direction);
        if (limit) d = d.limit(limit);
    }

    d = await d.toArray();

    return Promise.all(d.map(v => extractDocField(v, commands, projectName, dbName, dbUrl)));
}

export const writeMapDocument = async (commands, projectName, dbName, dbUrl) => {
    const t = await Promise.all(
        commands.value.map(async v => {
            writeDocument({ ...v }, projectName, dbName, dbUrl);
        })
    );

    return t;
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

                    const { userAuth: { auth, authToken } } = commands;

                    const rulesObj = {
                        ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                        endpoint: findOne ? _readDocument : _queryCollection,
                        prescription: {
                            path: collection,
                            direction,
                            sort,
                            limit,
                            find: findOne || find
                        },
                        dbName,
                        dbUrl
                    };

                    try {
                        await Scoped.InstancesData[projectName].databaseRules(rulesObj);
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

const dbRoute = [
    _readDocument,
    _writeDocument,
    _queryCollection,
    _writeMapDocument,
    _documentCount
];

const validateFilter = () => {

}

const validateWriteValue = (scope, value) => {

}

const validateFindConfig = () => {

}

const scopeList = ['setOne', 'setMany', 'updateOne', 'mergeOne', 'deleteOne', 'deleteMany', 'replaceOne', 'putOne'],
    directionList = [1, -1, 'asc', 'desc', 'ascending', 'descending'];

const validateDbBody = (body, route) => {
    const { commands, dbName, dbUrl } = body;

    if (dbName && typeof dbName !== 'string')
        throw simplifyError('invalid_dbName', 'dbName must be a string value');
    if (dbUrl && typeof dbUrl !== 'string')
        throw simplifyError('invalid_dbUrl', 'dbUrl must be a string value');

    if (route === '_writeMapDocument') {
        Object.entries(commands).forEach(([k, v]) => {
            if (k === 'value') {
                if (Array.isArray(v)) {
                    v.forEach((b, i) => {
                        Object.entries(b).forEach(([f, n]) => {
                            if (f === 'scope' && !scopeList.includes(n))
                                throw simplifyError('invalid_scope', `Invalid scope provided, got "${n}" but expected any of "${scopeList.join(', ')}"`);
                            if (f === 'find') validateFilter(n);
                            if (f === 'path' && (typeof n !== 'string' || !n.trim()))
                                throw simplifyError('invalid_path', `"path" is required and must be a string but got "${n}"`);
                            if (f === 'value') validateWriteValue(f, n);
                        });
                        if (!b.path) throw simplifyError('invalid_path', `"path" is required and must be a string`);
                        if (!b.scope) throw simplifyError('required_field', `scope is required field at index ${i}`);
                    });
                } else throw simplifyError('invalid_field_type', `"value" must be an array`);
            } else throw simplifyError('invalid_field', `Unknown field "${k}"`);
        });
    } else if (route === '_readDocument' || route === '_listenDocument') {
        Object.entries(commands).forEach(([k, v]) => {
            if (k === 'path') {
                if (typeof v !== 'string' || !v.trim())
                    throw simplifyError('invalid_path', `"path" is required and must be a string but got "${v}"`);
            } else if (k === 'find') {
                validateFilter(v);
            } else if (k === 'config') {
                validateFindConfig(v);
            } else if (v !== undefined) throw simplifyError('invalid_field', `Unknown field "${k}"`);
        });
        if (!commands.path) throw simplifyError('invalid_path', '"path" is required and must be a string');
    } else if (route === '_queryCollection' || route === '_listenCollection') {
        Object.entries(commands).forEach(([k, v]) => {
            if (k === 'path') {
                if (typeof v !== 'string' || !v.trim())
                    throw simplifyError('invalid_path', `"path" is required and must be a string but got "${v}"`);
            } else if (k === 'find') {
                validateFilter(v);
            } else if (k === 'sort') {
                if (v !== undefined && typeof v !== 'string')
                    throw simplifyError('invalid_field_value', '"sort" must be a boolean value');
            } else if (k === 'direction') {
                if (v !== undefined && !directionList.includes(v))
                    throw simplifyError('invalid_direction', `"direction" must be any of "${directionList.join(', ')}" but got ${v}`);
            } else if (k === 'limit') {
                if (v !== undefined && (!IS_WHOLE_NUMBER(v) || v <= 0))
                    throw simplifyError('invalid_field_value', '"limit" must be a positive whole number greater than zero');
            } else if (k === 'random') {
                if (v !== undefined && typeof v !== 'boolean')
                    throw simplifyError('invalid_field_value', '"random" must be a boolean value');
            } else if (k === 'config') {
                validateFindConfig(v);
            } else if (v !== undefined) throw simplifyError('invalid_field', `Unknown field "${k}"`);
        });
        if (!commands.path) throw simplifyError('invalid_path', '"path" is required and must be a string');
    } else if (route === '_writeDocument' || route === '_startDisconnectWriteTask') {
        Object.entries(commands).forEach(([f, n]) => {
            if (f === 'scope' && !scopeList.includes(n))
                throw simplifyError('invalid_scope', `Invalid scope provided, got "${n}" but expected any of "${scopeList.join(', ')}"`);
            if (f === 'find') validateFilter(n);
            if (f === 'path' && (typeof n !== 'string' || !n.trim()))
                throw simplifyError('invalid_path', `"path" is required and must be a string but got "${n}"`);
            if (f === 'value') validateWriteValue(f, n);
        });
        if (!commands.path) throw simplifyError('invalid_path', `"path" is required and must be a string`);
        if (!commands.scope) throw simplifyError('required_field', `scope is required field`);
    } else if (route === '_documentCount') {
        Object.entries(commands).forEach(([k, v]) => {
            if (k === 'path') {
                if (typeof v !== 'string' || !v.trim())
                    throw simplifyError('invalid_path', `"path" is required and must be a string but got "${v}"`);
            } else if (k === 'find') {
                validateFilter(v);
            } else if (v !== undefined) throw simplifyError('invalid_field', `Unknown field "${k}"`);
        });
        if (!commands.path) throw simplifyError('invalid_path', '"path" is required and must be a string');
    }
}

export const databaseRoutes = ({ projectName, logger, accessKey, enforceE2E_Encryption }) => [
    ...(enforceE2E_Encryption ? [] : dbRoute.map(v => ({ mroute: v, route: v }))),
    ...dbRoute.map(v => ({ mroute: btoa(v), route: v, ugly: true }))
].map(({ route, mroute, ugly }) =>
    express.Router({ caseSensitive: true }).post(`/${mroute}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('database'),
            now = Date.now();

        if (hasLogger) console.log(`started route: ${route}`);

        try {
            const { 'mosquito-token': authTokenx, authorization } = req.headers;

            if (authorization !== accessKey)
                throw simplifyError('incorrect_access_key', 'The accessKey been provided is not correct');

            let reqBody, clientPublicKey, authToken = authTokenx;

            if (ugly) {
                const [body, clientKey, atoken] = deserializeE2E(req.body, projectName);

                authToken = atoken;
                reqBody = body;
                clientPublicKey = clientKey;
            } else reqBody = req.body;

            validateDbBody(reqBody, route);

            const auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : undefined;
            const { commands, dbName, dbUrl } = reqBody;

            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                endpoint: route,
                prescription: { ...commands },
                dbName,
                dbUrl
            };

            try {
                await Scoped.InstancesData[projectName].databaseRules(rulesObj);
            } catch (e) {
                throw simplifyError('security_error', `${e}`);
            }

            const makeResult = (b) => {
                return ugly ? { e2e: serializeE2E(b, clientPublicKey, projectName) } : b;
            }

            switch (route) {
                case _readDocument:
                    const result = await readDocument({
                        ...commands,
                        userAuth: { auth, authToken }
                    }, projectName, dbName, dbUrl);

                    res.status(200).send(makeResult({ status: 'success', result }));
                    break;
                case _queryCollection:
                    const result1 = await queryDocument({
                        ...commands,
                        userAuth: { auth, authToken }
                    }, projectName, dbName, dbUrl);

                    res.status(200).send(makeResult({ status: 'success', result: result1 }));
                    break;
                case _writeDocument:
                    const committed = await writeDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send(makeResult({ status: 'success', committed: committed }));
                    break;
                case _writeMapDocument:
                    const committed1 = await writeMapDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send(makeResult({ status: 'success', committed: committed1 }));
                    break;
                case _documentCount:
                    const counts = await getDB(projectName, dbName, dbUrl).collection(commands.path).countDocuments(commands.find || {});
                    res.status(200).send(makeResult({ status: 'success', result: counts }));
                    break;
            }
        } catch (e) {
            if (hasLogger) console.error(`errRoute: /${route} err:`, e);
            res.status(403).send({
                status: 'error',
                ...simplifyCaughtError(e)
            });
        }
        if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
    })
);

export const databaseLivePath = [
    _listenCollection,
    _listenDocument,
    _startDisconnectWriteTask,
    _cancelDisconnectWriteTask
];

const validateLiveDbBody = validateDbBody;

export const databaseLiveRoutes = ({
    projectName,
    accessKey,
    logger,
    enforceE2E_Encryption
}) => [
    ...(enforceE2E_Encryption ? [] : databaseLivePath.map(v => ({ mroute: v, route: v }))),
    ...databaseLivePath.map(v => ({ mroute: btoa(v), route: v, ugly: true }))
].map(({ mroute, route, ugly }) =>
    handleSocketPlug(mroute, async (socket, roof, acknowledged) => {
        const hasLogger = logger.includes('all') || logger.includes('database'),
            now = Date.now();

        if (hasLogger) console.log(`started route: /${route}`);

        const initAuthshake = socket.handshake.auth;
        let authshakeObj,
            residueError,
            clientPublicKey,
            mtoken = initAuthshake?.mtoken;

        if (ugly) {
            try {
                const [body, clientKey, atoken] = deserializeE2E(initAuthshake.e2e, projectName);

                mtoken = atoken;
                authshakeObj = body;
                clientPublicKey = clientKey;
            } catch (e) { residueError = e; }
        } else authshakeObj = initAuthshake;

        const { accessKey: ak, _body: reqBody } = authshakeObj;
        let auth = mtoken ? niceTry(() => validateJWT(mtoken, projectName)) : undefined;

        if (!residueError && ak !== accessKey)
            residueError = simplifyError('incorrect_access_key', 'The accessKey been provided is not correct');

        validateLiveDbBody(reqBody, route);

        const { commands, dbName, dbUrl } = reqBody || {},
            { path, find } = commands || {},
            isDocumentWatch = route === _listenDocument;

        if (route === _listenDocument || route === _listenCollection) {
            try {
                let emission, hasDisconnect, lastEmittedValue = null;

                socket.on('disconnect', () => {
                    hasDisconnect = true;
                    lastEmittedValue = null;
                    emission?.();
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                });

                auth = await auth;
                if (hasDisconnect) return;

                const rulesObj = {
                    ...(auth ? { auth: { ...auth, token: mtoken } } : {}),
                    endpoint: route,
                    prescription: { ...commands },
                    dbName,
                    dbUrl
                };

                if (residueError) throw residueError;
                try {
                    await Scoped.InstancesData[projectName].databaseRules(rulesObj);
                    if (hasDisconnect) return;
                } catch (e) {
                    if (hasDisconnect) return;
                    throw simplifyError('security_error', `${e}`);
                }

                const callSnapshot = async () => {
                    const a = await (isDocumentWatch ? readDocument : queryDocument)({
                        ...commands,
                        userAuth: { auth, authToken: mtoken }
                    }, projectName, dbName, dbUrl);
                    if (hasDisconnect) return;

                    if (!isEqual(a, lastEmittedValue)) {
                        const s = ugly ? serializeE2E(a, clientPublicKey, projectName) : a;
                        socket.emit('mSnapshot', [undefined, s]);
                    }
                    lastEmittedValue = a;
                }

                callSnapshot();
                emission = emitDatabase(path, async () => {
                    try {
                        if (auth) await validateJWT(mtoken, projectName);
                        callSnapshot();
                    } catch (e) {
                        socket.emit('mSnapshot', [simplifyCaughtError(e), undefined]);
                    }
                }, projectName, dbName, dbUrl, { pipeline: { ...find } });
            } catch (e) {
                if (hasLogger) console.error('listenDoc err:', e);
                socket.emit('mSnapshot', [simplifyCaughtError(e), undefined]);
            }
        } else if (route === _startDisconnectWriteTask) {
            let hasDisconnect;

            try {
                socket.on('disconnect', async () => {
                    hasDisconnect = true;
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                    if (roof.writeTask) {
                        try {
                            if (auth) await validateJWT(mtoken, projectName);
                            const committed = await writeDocument(commands, projectName, dbName, dbUrl);
                            DisconnectionWriteTaskListener.dispatch(projectName, {
                                status: 'completed',
                                committed,
                                task: roof.writeTask
                            });
                            roof.writeTask = undefined;
                        } catch (e) { }
                    }
                });
                auth = await auth;

                if (hasDisconnect) return;
                if (residueError) throw residueError;
                const rulesObj = {
                    ...(auth ? { auth: { ...auth, token: mtoken } } : {}),
                    endpoint: route,
                    prescription: { ...commands },
                    dbName,
                    dbUrl
                };

                try {
                    await Scoped.InstancesData[projectName].databaseRules(rulesObj);
                    if (hasDisconnect) return;
                } catch (e) {
                    if (hasDisconnect) return;
                    throw simplifyError('security_error', `${e}`);
                }
                roof.writeTask = { commands, dbName, dbUrl };
            } catch (e) {
                DisconnectionWriteTaskListener.dispatch(projectName, {
                    status: 'error',
                    ...simplifyCaughtError(e),
                    task: { commands, dbName, dbUrl }
                });
                if (hasLogger) console.error(`/${route} error: `, e);
            }
        } else if (route === _cancelDisconnectWriteTask) {
            DisconnectionWriteTaskListener.dispatch(projectName, { status: 'cancelled', task: roof.writeTask });
            roof.writeTask = undefined;
            acknowledged();
        }
    })
)