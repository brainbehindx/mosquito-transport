import express from "express";
import { deserializeE2E, encodeBinary, niceTry, serializeE2E } from "../../helpers/utils.js";
import { getDB, getDbInstance } from "./base.js";
import { validateJWT } from "../auth/tokenizer.js";
import { Scoped } from "../../helpers/variables.js";
import { EngineRoutes, ERRORS, NO_CACHE_HEADER } from "../../helpers/values.js";
import { guardArray, guardObject, GuardSignal, niceGuard, Validator } from "guard-object";
import { simplifyCaughtError, simplifyError } from 'simplify-error';
import { deserializeBSON, serializeToBase64 } from "./bson.js";
import cloneDeep from "lodash/cloneDeep.js";
import { statusErrorCode, useDDOS } from "../../helpers/ddos.js";
import { serialize } from "entity-serializer";
import { grab, poke, unpoke } from "poke-object";

export const TIMESTAMP = { $timestamp: 'now' };
export const TIMESTAMP_OFFSET = (v) => ({ $timestamp_offset: v });

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

    const k = getDB(projectName, dbName, dbUrl).collection(path);
    const deserializedValue = deserializeWriteValue(value);
    const findObj = find && cleanseFind(path, find, projectName, dbName, dbUrl);
    const g = await (
        (scope === 'delete' || scope === 'deleteOne') ? k.deleteOne(findObj)
            :
            scope === 'deleteMany' ? k.deleteMany(findObj)
                :
                (scope === 'set' || scope === 'setOne') ? k.insertOne({ ...deserializedValue })
                    :
                    scope === 'setMany' ? k.insertMany(deserializedValue)
                        :
                        (scope === 'update' || scope === 'merge' || scope === 'updateOne' || scope === 'mergeOne')
                            ? k.updateOne(findObj, { ...deserializedValue }, {
                                upsert: scope === 'merge' || scope === 'mergeOne'
                            })
                            :
                            (scope === 'updateMany' || scope === 'mergeMany') ? k.updateMany(findObj, { ...deserializedValue }, { upsert: scope === 'merge' })
                                :
                                scope === 'replaceOne' ? k.replaceOne(findObj, { ...deserializedValue })
                                    :
                                    scope === 'putOne' ? k.replaceOne(findObj, { ...deserializedValue }, { upsert: true })
                                        :
                                        ({ fatalThrow: simplifyError('unknown_scope', `Invalid scope '${scope}'`) })
    );

    if (g.fatalThrow) throw g.fatalThrow;

    return g;
};

const deserializeWriteValue = (value) => {
    if (!value) return value;

    if (niceGuard(TIMESTAMP, value)) {
        return Date.now();
    } else if (niceGuard(TIMESTAMP_OFFSET(GuardSignal.NUMBER), value)) {
        return Date.now() + (value.$timestamp_offset);
    } else if (Validator.OBJECT(value)) {
        return Object.fromEntries(
            Object.entries(value).map(([k, v]) =>
                Validator.JSON(v) ? [k, deserializeWriteValue(v)] : [k, v]
            )
        );
    } else if (Array.isArray(value)) {
        return value.map(deserializeWriteValue);
    } else return value;
};

const cleanseFind = (path, find, projectName, dbName, dbUrl) => {
    const { defaultName, instance } = getDbInstance(projectName, dbUrl);
    dbName = dbName || defaultName;

    if (instance.__intercepted) {
        const d = instance.interceptMap?.map?.[dbName]?.[path];
        if (d?.fulltext) return find;
    }
    return cleanseFindCore(find);
}

const cleanseFindCore = (find) => {
    if (!find) return find;

    if (Validator.OBJECT(find)) {
        return Object.fromEntries(
            Object.entries(find).map(([k, v]) => {
                if (Validator.JSON(v)) {
                    if (
                        k === '$text' &&
                        Validator.OBJECT(v) &&
                        (Array.isArray(v.$field) || typeof v.$field === 'string')
                    ) {
                        const { $field, ...rest } = v;
                        return [k, rest];
                    }
                    return [k, cleanseFindCore(v)];
                }

                return [k, v];
            })
        );
    } else if (Array.isArray(find)) {
        return find.map(v => cleanseFindCore(v));
    } else return find;
}

const RawValueInstructions = {
    bsonRegExp: true,
    promoteLongs: false,
    promoteValues: false
};

export const readDocument = (commands, projectName, dbName, dbUrl) => {
    const { path, find, returnRawValue } = commands;
    return getDB(projectName, dbName, dbUrl).collection(path || '')
        .findOne(
            cleanseFind(path, { ...find }, projectName, dbName, dbUrl),
            returnRawValue ? RawValueInstructions : undefined
        );
};

export const readDocumentExtraction = async (commands, projectName, dbName, dbUrl) => {
    const d = await readDocument(commands, projectName, dbName, dbUrl);
    const doc_holder = {};
    const data = await extractDocField(d, commands, projectName, dbName, dbUrl, doc_holder);

    return { data, doc_holder };
};

export const queryDocument = (commands, projectName, dbName, dbUrl) => {
    const { path, find, limit, sort, direction, random, returnRawValue } = commands;
    let d = getDB(projectName, dbName, dbUrl).collection(path);
    const findObj = cleanseFind(path, { ...find }, projectName, dbName, dbUrl);

    if (random === true) {
        d = d.aggregate(
            [
                { $sample: { size: limit } },
                { $match: findObj }
            ],
            returnRawValue ? RawValueInstructions : undefined
        );
    } else {
        d = d.find(findObj, returnRawValue ? RawValueInstructions : undefined);
        if (sort) d = d.sort(sort, direction);
        if (limit) d = d.limit(limit);
    }

    return d.toArray();
};

export const queryDocumentExtraction = async (commands, projectName, dbName, dbUrl) => {
    const d = await queryDocument(commands, projectName, dbName, dbUrl);
    const doc_holder = {};
    const data = await Promise.all(d.map(v => extractDocField(v, commands, projectName, dbName, dbUrl, doc_holder)));

    return { data, doc_holder };
};

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
};

export const assignExtractionFind = (data, find) => {
    if (!find) return find;

    if (niceGuard({ $dynamicValue: GuardSignal.NON_EMPTY_STRING }, find)) {
        return grab(data, find.$dynamicValue) || null;
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

const snipDocument = (data, find, config) => {
    if (!data || !config) return data;
    const { returnOnly, excludeFields } = config || {};

    let output = { ...data };

    if (returnOnly) {
        output = {};
        (Array.isArray(returnOnly) ? returnOnly : [returnOnly]).filter(v => v).forEach(e => {
            const thisData = grab(data, e);
            if (thisData) poke(output, e, thisData);
        });
    } else if (excludeFields) {
        (Array.isArray(excludeFields) ? excludeFields : [excludeFields]).filter(v => v).forEach(e => {
            if (grab(data, e) && e !== '_id') unpoke(output, e);
        });
    }

    getFindFields(find).forEach(field => {
        if (!grab(output, field)) {
            const mainData = grab(data, field);
            if (mainData !== undefined) poke(output, field, mainData);
        }
    });

    return output;
};

const getFindFields = (find) => {
    const result = ['_id'];

    Object.entries(find).forEach(([k, v]) => {
        if (['$and', '$or', '$nor'].includes(k)) {
            v.forEach(e => {
                result.push(...getFindFields(e));
            });
        } else if (k === '$text') {
            result.push(...Array.isArray(v.$field) ? v.$field : [v.$field]);
        } else if (!k.startsWith('$')) {
            result.push(k);
        }
    });

    return result.filter((v, i, a) => a.findIndex(b => b === v) === i);
};

const extractDocField = async (d, commands, projectName, dbName, dbUrl, doc_holder) => {
    let finalData = d ? { ...d } : undefined;

    if (d) {
        const { extraction } = commands.config || {};
        finalData = snipDocument(d, commands.find, commands.config);

        const foreignDoc = Array.isArray(extraction) ? extraction : [extraction];

        if (extraction) {
            const extractedResult = await Promise.all(
                foreignDoc.map(async t => {
                    const { collection, direction, sort, limit, find, findOne } = t;
                    const exFind = cleanseFind(collection, assignExtractionFind(d, find || findOne), projectName, dbName, dbUrl);
                    const finder = find ? 'find' : 'findOne';

                    let colRef = getDB(projectName, dbName, dbUrl).collection(collection)[finder](exFind);

                    if (sort) colRef = colRef.sort(sort, direction);
                    if (limit) colRef = colRef.limit(limit);
                    if (find) colRef = colRef.toArray();
                    const result = await colRef;
                    const extractionHash = serializeToBase64({
                        _: { [finder]: exFind, sort, limit, collection }
                    });

                    doc_holder[extractionHash] = Array.isArray(result) ?
                        result.map(v => snipDocument(v, find || findOne, t))
                        : snipDocument(result, find || findOne, t);

                    return extractionHash;
                })
            );
            finalData._foreign_doc = Array.isArray(extraction) ? extractedResult : extractedResult[0];
        }
    }

    return finalData;
};

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
            documentKey: documentKey._id,
            insertion: ops === 'insert' ? fullDocument : undefined,
            deletion: ops === 'delete' ? documentKey._id : undefined,
            update: ops === 'update' ? { ...updateDescription } : undefined,
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
};

export const dbRoute = [
    _readDocument,
    _writeDocument,
    _queryCollection,
    _writeMapDocument,
    _documentCount
];

// TODO: provide valid footprint
const FilterFootPrint = t => true;
const UpdateValueFootPrint = () => true;
const InsertValueFootPrint = () => true;

const ReturnAndExcludeFootprint = t => t === undefined ||
    !(Array.isArray(t) ? t : [t]).filter(v => !Validator.TRIMMED_NON_EMPTY_STRING(v)).length;

const ConfigFootPrint = t => t === undefined ||
    guardObject({
        extraction: t => t === undefined ||
            (Array.isArray(t) ? t : [t]).filter(m =>
                guardObject({
                    collection: GuardSignal.TRIMMED_NON_EMPTY_STRING,
                    sort: (t, p) => t === undefined || (Validator.TRIMMED_NON_EMPTY_STRING(t) && p.find),
                    direction: (t, p) => t === undefined || (p.sort && p.find && DirectionList.includes(t)),
                    limit: (t, p) => t === undefined || (Validator.POSITIVE_INTEGER(t) && p.find),
                    find: (t, p) => (t === undefined && p.findOne) || (!p.findOne && FilterFootPrint(t)),
                    findOne: (t, p) => (t === undefined && p.find) || (!p.find && FilterFootPrint(t)),
                    returnOnly: ReturnAndExcludeFootprint,
                    excludeFields: ReturnAndExcludeFootprint
                }).validate(m)
            ).length,
        returnOnly: ReturnAndExcludeFootprint,
        excludeFields: ReturnAndExcludeFootprint
    }).validate(t);

const ScopeList = ['setOne', 'setMany', 'updateOne', 'updateMany', 'mergeOne', 'mergeMany', 'deleteOne', 'deleteMany', 'replaceOne', 'putOne'];
const DirectionList = [1, -1, 'asc', 'desc', 'ascending', 'descending'];

const CommonWriteFootPrint = {
    scope: t => ScopeList.includes(t),
    path: GuardSignal.TRIMMED_NON_EMPTY_STRING,
    find: FilterFootPrint,
    value: (t, p) => p.scope === 'setMany' ? (Array.isArray(t) && t.length && !t.filter(v => !InsertValueFootPrint(v)).length) :
        ['setOne', 'replaceOne', 'putOne'].includes(p.scope) ? InsertValueFootPrint(t) :
            ['updateOne', 'mergeOne', 'updateMany', 'mergeMany'].includes(p.scope) ? UpdateValueFootPrint(t) :
                (t === undefined || t === null)
};

const CommonQueryFootPrint = {
    path: GuardSignal.TRIMMED_NON_EMPTY_STRING,
    find: FilterFootPrint,
    sort: t => t === undefined || Validator.TRIMMED_NON_EMPTY_STRING(t),
    direction: (t, p) => t === undefined || (p.sort && DirectionList.includes(t)),
    limit: t => t === undefined || Validator.POSITIVE_INTEGER(t),
    random: (t, p) => t === undefined || (!p.sort && t === true),
    config: ConfigFootPrint
};

const CommonReadFootPrint = {
    path: GuardSignal.TRIMMED_NON_EMPTY_STRING,
    find: FilterFootPrint,
    config: ConfigFootPrint,
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
    [_startDisconnectWriteTask]: {
        connectTask: (v, p) => (v === undefined && p.disconnectTask) ||
            guardObject(CommandFootprint[_writeMapDocument]).validate(v),
        disconnectTask: (v, p) => (v === undefined && p.connectTask) ||
            guardObject(CommandFootprint[_writeMapDocument]).validate(v)
    },
    [_cancelDisconnectWriteTask]: CommonWriteFootPrint,
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
};

const transformBSON = (c, cast) => {
    if (c.config) c.config = deserializeBSON(c.config, cast);
    if (c.find) c.find = deserializeBSON(c.find, cast);
    if (c.value) c.value = deserializeBSON(c.value, cast)._;
};

export const databaseRoutes = ({ projectName, logger, enforceE2E_Encryption, castBSON, ddosMap, internals, ipNode }) => [
    ...enforceE2E_Encryption ? [] : dbRoute.map(v => ({ mroute: v, route: v })),
    ...dbRoute.map(v => ({ mroute: `e2e/${encodeBinary(v)}`, route: v, ugly: true }))
].map(({ route, mroute, ugly }) =>
    express.Router({ caseSensitive: true }).post(`/${mroute}`, async (req, res) => {
        const hasLogger = logger.includes('all') || logger.includes('database'),
            now = hasLogger && Date.now();

        if (hasLogger) console.log(`started route: /${route}`);
        res.set(NO_CACHE_HEADER);

        try {
            if (
                internals?.database === false ||
                (Array.isArray(internals?.database) && !internals.database.some(v => v === route))
            ) throw ERRORS.DISABLE_FEATURE;
            const ddosRouting = {
                [_readDocument]: 'read',
                [_queryCollection]: 'query',
                [_writeDocument]: 'write',
                [_writeMapDocument]: 'write',
                [_documentCount]: 'read'
            }[route];

            useDDOS(ddosMap, ddosRouting, 'database', req, ipNode);
            const { 'mosquito-token': authTokenx } = req.headers;

            let reqBody, clientPublicKey, authToken = authTokenx;

            if (ugly) {
                const [body, clientKey, atoken] = await deserializeE2E(req.body, projectName);

                authToken = atoken;
                reqBody = body;
                clientPublicKey = clientKey;
            } else reqBody = req.body;
            reqBody = cloneDeep(reqBody);

            const { commands, dbName, dbUrl } = reqBody;
            let clonedCommand;

            if (castBSON) {
                clonedCommand = cloneDeep(commands);
                transformBSON(clonedCommand, true);
            }
            transformBSON(commands, false);

            validateDbBody(reqBody, route);

            const auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : undefined;

            const rulesObj = {
                headers: { ...req.headers },
                ...auth ? { auth: { ...auth, token: authToken } } : {},
                endpoint: route,
                prescription: { ...castBSON ? clonedCommand : cloneDeep(commands) },
                dbName,
                dbUrl
            };

            try {
                await Scoped.InstancesData[projectName].databaseRules(rulesObj);
            } catch (e) {
                throw simplifyError('security_error', `${e}`);
            }

            const makeResult = async (b) => {
                return ugly ? serialize([await serializeE2E(b, clientPublicKey, projectName)]) : b;
            }

            switch (route) {
                case _readDocument:
                    const result = await readDocumentExtraction({
                        ...commands,
                        returnRawValue: true
                    }, projectName, dbName, dbUrl);

                    res.status(200).send(await makeResult({ status: 'success', result: serializeToBase64({ _: result }) }));
                    break;
                case _queryCollection:
                    const result1 = await queryDocumentExtraction({
                        ...commands,
                        returnRawValue: true
                    }, projectName, dbName, dbUrl);

                    res.status(200).send(await makeResult({ status: 'success', result: serializeToBase64({ _: result1 }) }));
                    break;
                case _writeDocument:
                    const statusData = await writeDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send(await makeResult({ status: 'success', statusData }));
                    break;
                case _writeMapDocument:
                    const committed1 = await writeMapDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send(await makeResult({ status: 'success', statusData: committed1 }));
                    break;
                case _documentCount:
                    const counts = await getDB(projectName, dbName, dbUrl).collection(commands.path).countDocuments(commands.find || {});
                    res.status(200).send(await makeResult({ status: 'success', result: counts }));
                    break;
            }
        } catch (e) {
            if (logger.includes('all') || logger.includes('error')) console.error(`errRoute: /${route} err:`, e);
            const result = { status: 'error', ...simplifyCaughtError(e) };

            res.status(statusErrorCode(e)).send(ugly ? serialize([undefined, result]) : result);
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

/**
 * @type {(config: any) => (socket: import('socket.io').Socket)=> void}
 */
export const databaseLiveRoutesHandler = ({
    projectName,
    logger,
    enforceE2E_Encryption,
    castBSON,
    internals
}) => (socket) => {
    const { auth: initAuthshake, headers } = socket.handshake;
    const routeList = [
        ...enforceE2E_Encryption ? [] : databaseLivePath.map(v => ({ mroute: v, route: v })),
        ...databaseLivePath.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
    ];
    const routeObj = routeList.find(v => v.mroute === initAuthshake._m_route);
    if (!routeObj) return;
    const hasLogger = logger.includes('all') || logger.includes('database'),
        now = Date.now();
    const hasErrorLoger = logger.includes('all') || logger.includes('error');

    let taskWriter;

    const { route, ugly } = routeObj;

    (async () => {
        if (hasLogger) console.log(`started route: /${route}`);

        let authshakeObj,
            residueError,
            clientPublicKey,
            mtoken = initAuthshake?.mtoken;

        if (
            internals?.database === false ||
            (Array.isArray(internals?.database) && !internals.database.some(v => v === route))
        ) {
            residueError = ERRORS.DISABLE_FEATURE;
        }

        if (ugly) {
            try {
                const [body, clientKey, atoken] = await deserializeE2E(Buffer.from(initAuthshake.e2e, 'base64'), projectName);

                mtoken = atoken;
                authshakeObj = body;
                clientPublicKey = clientKey;
            } catch (e) { residueError = e; }
        } else authshakeObj = initAuthshake;

        const { _body: reqBody } = cloneDeep(authshakeObj);

        const { commands, dbName, dbUrl } = reqBody;
        const isDocumentWatch = route === _listenDocument;

        if (socket.disconnected) return;
        if (route === _listenDocument || route === _listenCollection) {
            try {
                if (residueError) throw residueError;
                let clonedCommand;

                if (castBSON) {
                    clonedCommand = cloneDeep(commands);
                    transformBSON(clonedCommand, true);
                }
                transformBSON(commands, false);
                validateLiveDbBody(reqBody, route);

                let emission, hasDisconnect, lastEmittedValue = null;

                socket.on('disconnect', () => {
                    hasDisconnect = true;
                    lastEmittedValue = null;
                    emission?.();
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                });
                const auth = mtoken ? await niceTry(() => validateJWT(mtoken, projectName)) : undefined;
                if (hasDisconnect) return;

                const rulesObj = {
                    headers: { ...headers },
                    ...auth ? { auth: { ...auth, token: mtoken } } : {},
                    endpoint: route,
                    prescription: { ...castBSON ? clonedCommand : cloneDeep(commands) },
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

                const callSnapshot = async () => {
                    const a = await (isDocumentWatch ? readDocumentExtraction : queryDocumentExtraction)({
                        ...commands,
                        returnRawValue: true
                    }, projectName, dbName, dbUrl);
                    if (hasDisconnect) return;
                    const newHash = serializeToBase64({ _: a });

                    if (newHash !== lastEmittedValue) {
                        const s = ugly ? await serializeE2E(newHash, clientPublicKey, projectName) : newHash;
                        socket.emit('mSnapshot', [undefined, s]);
                    }
                    lastEmittedValue = newHash;
                }

                callSnapshot();
                emission = emitDatabase(commands.path, async () => {
                    try {
                        if (auth) await validateJWT(mtoken, projectName);
                        callSnapshot();
                    } catch (e) {
                        socket.emit('mSnapshot', [simplifyCaughtError(e), undefined]);
                    }
                }, projectName, dbName, dbUrl, { pipeline: { ...commands.find } });
            } catch (e) {
                if (hasErrorLoger) console.error(`errRoute /${route} err:`, e);
                socket.emit('mSnapshot', [simplifyCaughtError(e), undefined]);
            }
        } else if (route === _startDisconnectWriteTask) {
            if (taskWriter === false) return;
            try {
                if (residueError) throw residueError;

                const { connectTask, disconnectTask } = commands;
                let clonedConnectCommand, clonedDisconnectCommand;

                if (castBSON) {
                    if (connectTask) {
                        clonedConnectCommand = cloneDeep(connectTask);
                        transformBSON(clonedConnectCommand, true);
                    }
                    if (disconnectTask) {
                        clonedDisconnectCommand = cloneDeep(disconnectTask);
                        transformBSON(clonedDisconnectCommand, true);
                    }
                }
                if (connectTask) transformBSON(connectTask, false);
                if (disconnectTask) transformBSON(disconnectTask, false);
                validateLiveDbBody(reqBody, route);

                socket.on('disconnect', async () => {
                    if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                    if (taskWriter) taskWriter('_disconnectionTask', false);
                });

                taskWriter = async (endpoint, isConnected) => {
                    const taskData = isConnected ? connectTask : disconnectTask;
                    if (!taskData) return;
                    const auth = mtoken ? await niceTry(() => validateJWT(mtoken, projectName)) : undefined;

                    const rulesObj = {
                        headers: { ...headers },
                        ...auth ? { auth: { ...auth, token: mtoken } } : {},
                        endpoint,
                        prescription: castBSON ? {
                            ...commands,
                            ...clonedConnectCommand ? { connectTask: clonedConnectCommand } : {},
                            ...clonedDisconnectCommand ? { disconnectTask: clonedDisconnectCommand } : {}
                        } : cloneDeep(commands),
                        dbName,
                        dbUrl
                    };

                    await Scoped.InstancesData[projectName].databaseRules(rulesObj);
                    if (isConnected && socket.disconnected) return;
                    await writeMapDocument(taskData, projectName, dbName, dbUrl);
                }
                await taskWriter('_connectionTask', true);
            } catch (e) {
                if (hasErrorLoger) console.error(`errRoute: /${route} err: `, e);
            }
        }
    })();

    if (route === _startDisconnectWriteTask) {
        const { mroute } = routeList.find(v => v.route === _cancelDisconnectWriteTask && v.ugly === ugly);
        socket.on(mroute, (acknowledged) => {
            if (hasLogger) console.log(`started route: /${_cancelDisconnectWriteTask}`);
            taskWriter = false;
            acknowledged();
        });
    }
};