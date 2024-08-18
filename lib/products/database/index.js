import express from "express";
import { deserializeE2E, encodeBinary, niceTry, serializeE2E } from "../../helpers/utils.js";
import { getDB } from "./base.js";
import getLodash from 'lodash.get';
import setLodash from 'lodash.set';
import unsetLodash from 'lodash.unset';
import { validateJWT } from "../auth/tokenizer.js";
import { Scoped } from "../../helpers/variables.js";
import { handleSocketPlug } from "../../helpers/socket_handler.js";
import { EngineRoutes } from "../../helpers/values.js";
import { DisconnectionWriteTaskListener } from "../../helpers/listeners.js";
import { guardArray, guardObject, GuardSignal, niceGuard, Validator } from "guard-object";
import stringify from "fast-json-stable-stringify";
import { simplifyCaughtError, simplifyError } from 'simplify-error';

export const TIMESTAMP = { $timestamp: 'now' };

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

    if (niceGuard(TIMESTAMP, value)) {
        return Date.now();
    } else if (Validator.OBJECT(value)) {
        return Object.fromEntries(
            Object.entries(value).map(([k, v]) =>
                Validator.JSON(v) ? [k, deserializeWriteValue(v)] : [k, v]
            )
        );
    } else if (Array.isArray(value)) {
        return value.map(deserializeWriteValue);
    } else return value;
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
    if (commands.stepping) {
        const t = [];
        for (let i = 0; i < commands.value.length; i++) {
            t.push(await writeDocument({ ...commands.value[i] }, projectName, dbName, dbUrl));
        }
        return t;
    } else {
        const t = await Promise.all(
            commands.value.map(async v =>
                writeDocument({ ...v }, projectName, dbName, dbUrl)
            )
        );
        return t;
    }
}

export const assignExtractionFind = (data, find) => {
    if (!find) return find;

    if (niceGuard({ $dynamicValue: GuardSignal.NON_EMPTY_STRING }, find)) {
        return getLodash(data, find.$dynamicValue);
    } else if (Validator.OBJECT(find)) {
        return Object.fromEntries(
            Object.entries(find).map(([k, v]) =>
                Validator.JSON(v) ? [k, assignExtractionFind(data, v)] : [k, v]
            )
        );
    } else if (Array.isArray(find)) {
        return find.map(v => assignExtractionFind(data, v));
    } else return find;
};

const snipDocument = (data, config) => {
    if (!data || !config) return data;
    const { returnOnly, excludeFields } = config || {};

    let output = { ...data };

    if (returnOnly) {
        output = { _id: data._id };
        (Array.isArray(returnOnly) ? returnOnly : [returnOnly]).filter(v => v).forEach(e => {
            const thisData = getLodash(data, e);
            if (thisData) setLodash(output, e, thisData);
        });
    } else if (excludeFields) {
        (Array.isArray(excludeFields) ? excludeFields : [excludeFields]).filter(v => v).forEach(e => {
            if (getLodash(data, e) && e !== '_id') unsetLodash(output, e);
        });
    }

    return output;
}

const extractDocField = async (d, commands, projectName, dbName, dbUrl) => {
    let finalData = d ? { ...d } : undefined;

    if (d) {
        const { extraction } = commands.config || {};
        finalData = snipDocument(d, commands.config);

        const foreignDoc = Array.isArray(extraction) ? extraction : [extraction];

        if (extraction) {
            const extractedResult = await Promise.all(
                foreignDoc.map(t => async () => {
                    const { collection, direction, sort, limit, find, findOne } = t;
                    const exFind = assignExtractionFind(d, find || findOne);

                    let colRef = getDB(projectName, dbName, dbUrl).collection(collection)[find ? 'find' : 'findOne'](exFind);

                    if (sort) colRef = colRef.sort(sort, direction);
                    if (limit) colRef = colRef.limit(limit);
                    if (find) colRef = colRef.toArray();
                    const result = await colRef;

                    return Array.isArray(result) ? result.map(v => snipDocument(v, t)) : snipDocument(result);
                })
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
            fullDocument: includeAfterData ? 'whenAvailable' : undefined,
            fullDocumentBeforeChange: includeBeforeData ? 'whenAvailable' : undefined
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
            timestamp: clusterTime?.toNumber?.(),
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

const FilterFootPrint = t => { };
const UpdateValueFootPrint = {};
const InsertValueFootPrint = {};

const ReturnAndExcludeFootprint = t => t === undefined ||
    !(Array.isArray(t) ? t : [t]).filter(v => !Validator.TRIMMED_NON_EMPTY_STRING(v)).length;

const ConfigFootPrint = t => t === undefined ||
    guardObject({
        extraction: t => t === undefined ||
            guardObject({
                collection: GuardSignal.TRIMMED_NON_EMPTY_STRING,
                sort: (t, p) => t === undefined || (Validator.TRIMMED_NON_EMPTY_STRING(t) && p.find),
                direction: (t, p) => t === undefined || (p.sort && p.find && DirectionList.includes(t)),
                limit: (t, p) => t === undefined || (Validator.POSITIVE_INTEGER(t) && p.find),
                find: (t, p) => (t === undefined && p.findOne) || (!p.findOne && FilterFootPrint(t)),
                findOne: (t, p) => (t === undefined && p.find) || (!p.find && FilterFootPrint(t)),
                returnOnly: ReturnAndExcludeFootprint,
                excludeFields: ReturnAndExcludeFootprint
            }).validate(t),
        returnOnly: ReturnAndExcludeFootprint,
        excludeFields: ReturnAndExcludeFootprint
    }).validate(t);

const ScopeList = ['setOne', 'setMany', 'updateOne', 'updateMany', 'mergeOne', 'mergeMany', 'deleteOne', 'deleteMany', 'replaceOne', 'putOne'],
    DirectionList = [1, -1, 'asc', 'desc', 'ascending', 'descending'];

const CommonWriteFootPrint = {
    scope: t => ScopeList.includes(t),
    path: GuardSignal.TRIMMED_NON_EMPTY_STRING,
    find: FilterFootPrint,
    value: (t, p) => p.scope === 'setMany' ? (Array.isArray(t) && t.length && !t.filter(v => !InsertValueFootPrint(v)).length) :
        ['setOne', 'replaceOne', 'putOne'].includes(p.scope) ? InsertValueFootPrint(t) :
            ['updateOne', 'mergeOne', 'updateMany', 'mergeMany'].includes(p.scope) ? UpdateValueFootPrint(t) :
                t === undefined
};

const CommonQueryFootPrint = {
    path: GuardSignal.TRIMMED_NON_EMPTY_STRING,
    find: FilterFootPrint,
    sort: t => t === undefined || Validator.TRIMMED_NON_EMPTY_STRING(t),
    direction: (t, p) => t === undefined || (p.sort && DirectionList.includes(t)),
    limit: t => t === undefined || Validator.POSITIVE_INTEGER(t),
    random: t => t === undefined || Validator.BOOLEAN(t),
    config: t => t === undefined || ConfigFootPrint(t)
};

const CommonReadFootPrint = {
    path: GuardSignal.TRIMMED_NON_EMPTY_STRING,
    find: FilterFootPrint,
    config: t => t === undefined || ConfigFootPrint(t),
};

const CommandFootprint = {
    [_writeMapDocument]: {
        value: guardArray(CommonWriteFootPrint),
        stepping: t => t === undefined || Validator.BOOLEAN(t)
    },
    [_readDocument]: CommonReadFootPrint,
    [_listenDocument]: CommonReadFootPrint,
    [_queryCollection]: CommonQueryFootPrint,
    [_listenCollection]: CommonQueryFootPrint,
    [_writeDocument]: CommonWriteFootPrint,
    [_startDisconnectWriteTask]: CommonWriteFootPrint,
    [_documentCount]: {
        path: GuardSignal.TRIMMED_NON_EMPTY_STRING,
        find: FilterFootPrint
    }
};

const validateDbBody = (body, route) => {
    guardObject({
        dbName: t => t === undefined || Validator.TRIMMED_NON_EMPTY_STRING(t),
        dbUrl: t => t === undefined || Validator.TRIMMED_NON_EMPTY_STRING(t),
        commands: CommandFootprint[route]
    }).validate(body);
}

export const databaseRoutes = ({ projectName, logger, accessKey, enforceE2E_Encryption }) => [
    ...(enforceE2E_Encryption ? [] : dbRoute.map(v => ({ mroute: v, route: v }))),
    ...dbRoute.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
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
    ...databaseLivePath.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
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

                    if (stringify(a) !== stringify(lastEmittedValue)) {
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