import express from "express";
import { encodeBinary } from "../../helpers/utils.js";
import { getDB } from "./base.js";
import { validateJWT } from "../auth/tokenizer.js";
import { Scoped } from "../../helpers/variables.js";
import { ADMIN_DB, DEFAULT_DB, EngineRoutes, ERRORS, NO_CACHE_HEADER } from "../../helpers/values.js";
import { guardArray, guardObject, GuardSignal, niceGuard, Validator } from "guard-object";
import { simplifyCaughtError, simplifyError } from 'simplify-error';
import { serializeToBase64 } from "./bson.js";
import { statusErrorCode, throwRateLimit, useDDOS } from "../../helpers/ddos.js";
import { serialize } from "entity-serializer";
import { grab, poke, unpoke } from "poke-object";
import { basicClone } from "../../helpers/basic_clone.js";
import e2e_worker from "../../helpers/e2e_worker.js";
import { Buffer } from "buffer";
import { EJSON } from "mongodb/lib/bson.js";

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

const writeDocument = async ({ scope: scopeX, find, value, path }, projectName, dbName, dbUrl) => {
    const scope = scopeX || 'setOne';

    const k = getDB(projectName, dbUrl, dbName).collection(path);
    const deserializedValue = deserializeWriteValue(value);
    const findObj = find && cleanseFind(path, find, projectName, dbName, dbUrl);

    const g = await (
        (scope === 'delete' || scope === 'deleteOne')
            ? k.deleteOne(findObj)
            : scope === 'deleteMany'
                ? k.deleteMany(findObj)
                : (scope === 'set' || scope === 'setOne')
                    ? k.insertOne({ ...deserializedValue })
                    : scope === 'setMany'
                        ? k.insertMany(deserializedValue)
                        : (scope === 'update' || scope === 'merge' || scope === 'updateOne' || scope === 'mergeOne')
                            ? k.updateOne(findObj, { ...deserializedValue }, {
                                upsert: scope === 'merge' || scope === 'mergeOne'
                            })
                            : (scope === 'updateMany' || scope === 'mergeMany')
                                ? k.updateMany(findObj, { ...deserializedValue }, { upsert: scope === 'merge' })
                                : scope === 'replaceOne'
                                    ? k.replaceOne(findObj, { ...deserializedValue })
                                    : scope === 'putOne'
                                        ? k.replaceOne(findObj, { ...deserializedValue }, { upsert: true })
                                        : ({ fatalThrow: simplifyError('unknown_scope', `Invalid scope '${scope}'`) })
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

const cleanseFind = (path, find, projectName, name, dbUrl) => {
    const db = getDB(projectName, dbUrl, name);

    if (db.__intercepted) {
        const d = db.client.interceptMap?.map?.[db.databaseName]?.[path];
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
    bsonRegExp: false,
    promoteLongs: true,
    promoteValues: true,
    promoteBuffers: true
};

const toExtendedJSON = (o) => JSON.parse(EJSON.stringify(o, { relaxed: false }));

const readDocument = (commands, projectName, dbName, dbUrl) => {
    const { path, find } = commands;
    return getDB(projectName, dbUrl, dbName)
        .collection(path || '')
        .findOne(
            cleanseFind(path, { ...find }, projectName, dbName, dbUrl),
            RawValueInstructions
        ).then(toExtendedJSON);
};

const readDocumentExtraction = async (commands, projectName, dbName, dbUrl) => {
    const d = await readDocument(commands, projectName, dbName, dbUrl);
    const doc_holder = {};
    const data = await extractDocField(d, commands, projectName, dbName, dbUrl, doc_holder);

    return { data, doc_holder };
};

const queryDocument = (commands, projectName, dbName, dbUrl) => {
    const { path, find, limit, sort, direction, random } = commands;
    let d = getDB(projectName, dbUrl, dbName).collection(path);
    const findObj = cleanseFind(path, { ...find }, projectName, dbName, dbUrl);

    if (random === true) {
        d = d.aggregate(
            [
                { $sample: { size: limit } },
                { $match: findObj }
            ],
            RawValueInstructions
        );
    } else {
        d = d.find(findObj, RawValueInstructions);
        if (sort) d = d.sort(sort, direction);
        if (limit) d = d.limit(limit);
    }

    return d.toArray().then(r => r.map(toExtendedJSON));
};

const queryDocumentExtraction = async (commands, projectName, dbName, dbUrl) => {
    const d = await queryDocument(commands, projectName, dbName, dbUrl);
    const doc_holder = {};
    const data = await Promise.all(d.map(v => extractDocField(v, commands, projectName, dbName, dbUrl, doc_holder)));

    return { data, doc_holder };
};

const writeMapDocument = async (commands, projectName, dbName, dbUrl) => {
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

const EXTRACTION_ERROR = {
    DYNAMIC_VALUE_404: '$dV_404'
};

const assignExtractionFind = (data, find) => {
    if (!find) return find;

    if (niceGuard({ $dynamicValue: GuardSignal.NON_EMPTY_STRING }, find)) {
        const value = grab(data, find.$dynamicValue);
        if (value === undefined) throw EXTRACTION_ERROR.DYNAMIC_VALUE_404;
        return value;
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
        (Array.isArray(returnOnly) ? returnOnly : [returnOnly])
            .filter(v => v)
            .forEach(e => {
                const thisData = grab(data, e);
                if (thisData) poke(output, e, thisData);
            });
    } else if (excludeFields) {
        (Array.isArray(excludeFields) ? excludeFields : [excludeFields])
            .filter(v => v)
            .forEach(e => {
                if (grab(data, e) && e !== '_id') unpoke(output, e);
            });
    }

    // inclusion of filter based fields for client mutation
    getFindFields(find).forEach(field => {
        if (!grab(output, field)) {
            const mainData = grab(data, field);
            if (mainData !== undefined)
                poke(output, field, mainData);
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
                    let prefilledFind;

                    try {
                        prefilledFind = assignExtractionFind(d, find || findOne);
                    } catch (error) {
                        if (error === EXTRACTION_ERROR.DYNAMIC_VALUE_404) {
                            if (!doc_holder.hasOwnProperty(error))
                                doc_holder[error] = find ? [] : undefined;

                            return error;
                        }
                        throw error;
                    }

                    const exFind = cleanseFind(collection, prefilledFind, projectName, dbName, dbUrl);
                    const finder = find ? 'find' : 'findOne';

                    let colRef = getDB(projectName, dbUrl, dbName).collection(collection)[finder](exFind);

                    if (sort) colRef = colRef.sort(sort, direction);
                    if (limit) colRef = colRef.limit(limit);
                    if (find) colRef = colRef.toArray();
                    const result = await colRef;
                    const extractionHash =
                        serializeToBase64({
                            _: { [finder]: exFind, sort, limit, collection }
                        });

                    if (!doc_holder.hasOwnProperty(extractionHash))
                        doc_holder[extractionHash] =
                            Array.isArray(result)
                                ? result.map(v => toExtendedJSON(snipDocument(v, find || findOne, t)))
                                : toExtendedJSON(snipDocument(result, find || findOne, t));

                    return extractionHash;
                })
            );

            finalData._foreign_doc =
                Array.isArray(extraction)
                    ? extractedResult
                    : extractedResult[0];
        }
    }

    return finalData;
};

export const emitDatabase = (path, callback, projectName, dbName, dbUrl, options) => {
    const naming = getDB(projectName, dbUrl, dbName);

    const nodeId = `${path}:${projectName}:${naming.databaseName}:${dbUrl}:${options && serializeToBase64(options)}`;
    let instance = Scoped.AccumulatedDatabaseEmittions[nodeId];

    if (!instance) {
        const callers = new Map();
        const destroy =
            internalEmitDatabase(path, (...args) => {
                callers.forEach(value => {
                    value(...args);
                });
            }, projectName, dbName, dbUrl, options);

        Scoped.AccumulatedDatabaseEmittions[nodeId] = (instance = { callers, destroy });
    }

    const ref = {};
    instance.callers.set(ref, callback);

    return () => {
        if (!instance.callers.has(ref)) return;
        instance.callers.delete(ref);
        if (!instance.callers.size) {
            instance.destroy();
            delete Scoped.AccumulatedDatabaseEmittions[nodeId];
        }
    }
}

const requiredEvent = ['insert', 'update', 'replace', 'delete'];

const internalEmitDatabase = (path, callback, projectName, dbName, dbUrl, options, resumeAfter) => {
    const { pipeline, ...restOptions } = options || {};

    const col = getDB(projectName, dbUrl, dbName).collection(path);
    const stream =
        col.watch(pipeline || [
            {
                $match: {
                    operationType: { $in: requiredEvent }
                }
            }
        ], {
            ...restOptions,
            resumeAfter
        });

    stream.on('change', l => {
        const { operationType: ops, fullDocument, fullDocumentBeforeChange, documentKey, updateDescription, clusterTime, ...rest } = l;

        if (!requiredEvent.includes(ops)) return;

        callback?.({
            documentKey: documentKey._id,
            insertion: ops === 'insert' ? fullDocument : undefined,
            update: ops === 'update' ? { ...updateDescription } : undefined,
            replacement: ops === 'replace' ? fullDocument : undefined,
            deletion: ops === 'delete' ? documentKey._id : undefined,
            before: fullDocumentBeforeChange,
            after: fullDocument,
            timestamp: clusterTime,
            operation: ops,
            extras: rest
        });
    });

    stream.on('resumeTokenChanged', (token) => {
        resumeAfter = token;
    });

    let closure = null;

    stream.on('error', async (error) => {
        await stream.close();
        setTimeout(() => {
            if (closure === null)
                closure = internalEmitDatabase(path, callback, projectName, dbName, dbUrl, options, resumeAfter);
        }, 7000);
        process.emit('uncaughtException', `emitDatabase error: ${error}`);
    });

    return () => {
        const thisClosure = closure;
        closure = undefined;

        if (thisClosure === null) {
            stream.close();
        } else if (typeof thisClosure === 'function') {
            thisClosure();
        }
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

const ReturnAndExcludeFootprint = t =>
    t === undefined ||
    !(Array.isArray(t) ? t : [t]).filter(v => !Validator.TRIMMED_NON_EMPTY_STRING(v)).length;

const ConfigFootPrint = t =>
    t === undefined ||
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
    value: (t, p) =>
        p.scope === 'setMany'
            ? (Array.isArray(t) && t.length && !t.filter(v => !InsertValueFootPrint(v)).length)
            : ['setOne', 'replaceOne', 'putOne'].includes(p.scope)
                ? InsertValueFootPrint(t)
                : ['updateOne', 'mergeOne', 'updateMany', 'mergeMany'].includes(p.scope)
                    ? UpdateValueFootPrint(t)
                    : (t === undefined || t === null)
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
        dbUrl: t => t === undefined || Validator.TRIMMED_NON_EMPTY_STRING(t),
        dbName: t => t === undefined || Validator.TRIMMED_NON_EMPTY_STRING(t),
        commands: CommandFootprint[route]
    }).validate(body);
};

const validateDbInstanceName = n => {
    if (n === ADMIN_DB)
        throw `remote clients are restricted from accessing '${ADMIN_DB}' database instance`;
}

const checkRemoteDbName = (dbName, allowDbNameFromRemoteClients) => {
    if (!allowDbNameFromRemoteClients && ![undefined, null].includes(dbName))
        throw `providing a custom database name of ('${dbName}') is restricted on this instance, kindly ask the server administrator to enable allowDbNameFromRemoteClients if you intended on providing a custom dbName`;
}

export const databaseRoutes = ({
    projectName,
    logger,
    enforceE2E_Encryption,
    ddosMap,
    internals,
    ipNode,
    allowDbNameFromRemoteClients
}) => {
    const hasLogger = logger.includes('all') || logger.includes('database');
    const hasErrorLoger = logger.includes('all') || logger.includes('error');

    return [
        ...enforceE2E_Encryption ? [] : dbRoute.map(v => ({ mroute: v, route: v })),
        ...dbRoute.map(v => ({ mroute: `e2e/${encodeBinary(v)}`, route: v, ugly: true }))
    ].map(({ route, mroute, ugly }) =>
        express.Router({ caseSensitive: true }).post(`/${mroute}`, async (req, res) => {
            const now = hasLogger && Date.now();

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

                useDDOS({
                    config: ddosMap,
                    requestPath: ddosRouting,
                    route: 'database',
                    ipNode,
                    req
                });

                const { mtoken } = req.headers;

                let reqBody,
                    clientPublicKey,
                    authToken = mtoken;

                if (ugly) {
                    const [body, clientKey, atoken] = await e2e_worker.decrypt(req.body, projectName);

                    reqBody = body;
                    clientPublicKey = clientKey;
                    authToken = atoken;
                } else reqBody = req.body;

                const { commands, dbName, dbUrl = DEFAULT_DB } = reqBody;

                validateDbInstanceName(dbUrl);
                validateDbBody(reqBody, route);
                checkRemoteDbName(dbName, allowDbNameFromRemoteClients);

                const auth =
                    authToken
                        ? await validateJWT(authToken, projectName).catch(() => null)
                        : undefined;

                const rulesObj = {
                    headers: { ...req.headers },
                    ...auth ? { auth } : {},
                    endpoint: route,
                    prescription: { ...basicClone(commands) },
                    dbInstance: dbUrl,
                    dbName
                };

                try {
                    await Scoped.InstancesData[projectName].databaseRules(rulesObj, throwRateLimit('database'));
                } catch (e) {
                    throw simplifyError('security_error', `${e}`);
                }

                const makeResult = async (b) => {
                    return ugly ? serialize([await e2e_worker.encrypt(b, clientPublicKey, projectName)]) : b;
                }

                switch (route) {
                    case _readDocument:
                        const result = await readDocumentExtraction(commands, projectName, dbName, dbUrl);

                        res.status(200).send(await makeResult({ status: 'success', result }));
                        break;
                    case _queryCollection:
                        const result1 = await queryDocumentExtraction(commands, projectName, dbName, dbUrl);

                        res.status(200).send(await makeResult({ status: 'success', result: result1 }));
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
                        const counts =
                            await getDB(projectName, dbUrl, dbName)
                                .collection(commands.path)
                                .countDocuments(commands.find || {});
                        res.status(200).send(await makeResult({ status: 'success', result: counts }));
                        break;
                }
            } catch (e) {
                if (hasErrorLoger)
                    console.error(`errRoute: /${route} err:`, e);

                const result = { status: 'error', ...simplifyCaughtError(e) };

                res.status(statusErrorCode(e)).send(ugly ? serialize([undefined, result]) : result);
            }
            if (hasLogger) console.log(`${route} took: ${Date.now() - now}ms`);
        })
    );
}

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
    internals,
    allowDbNameFromRemoteClients
}) => {
    const hasLogger = logger.includes('all') || logger.includes('database');
    const hasErrorLoger = logger.includes('all') || logger.includes('error');

    const routeList = [
        ...enforceE2E_Encryption ? [] : databaseLivePath.map(v => ({ mroute: v, route: v })),
        ...databaseLivePath.map(v => ({ mroute: encodeBinary(v), route: v, ugly: true }))
    ];

    return (socket) => {
        const { auth: initAuthshake, headers } = socket.handshake;
        const routeObj = routeList.find(v => v.mroute === initAuthshake._m_route);
        if (!routeObj) return;
        const now = hasLogger && Date.now();

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
                    const [body, clientKey, atoken] = await e2e_worker.decrypt(Buffer.from(initAuthshake.e2e, 'base64'), projectName);

                    authshakeObj = body;
                    clientPublicKey = clientKey;
                    mtoken = atoken;
                } catch (e) { residueError = e; }
            } else authshakeObj = initAuthshake;

            const { _body: reqBody } = basicClone(authshakeObj);

            const { commands, dbName, dbUrl = DEFAULT_DB } = reqBody;
            const isDocumentWatch = route === _listenDocument;

            if (socket.disconnected) return;
            if (route === _listenDocument || route === _listenCollection) {
                try {
                    if (residueError) throw residueError;

                    validateDbInstanceName(dbUrl);
                    validateLiveDbBody(reqBody, route);
                    checkRemoteDbName(dbName, allowDbNameFromRemoteClients);

                    let emission, hasDisconnect, lastEmittedValue = null;

                    socket.on('disconnect', () => {
                        hasDisconnect = true;
                        lastEmittedValue = null;
                        emission?.();
                        if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                    });
                    const auth =
                        mtoken
                            ? await validateJWT(mtoken, projectName).catch(() => null)
                            : undefined;
                    if (hasDisconnect) return;

                    const rulesObj = {
                        headers: { ...headers },
                        ...auth ? { auth } : {},
                        endpoint: route,
                        prescription: basicClone(commands),
                        dbName,
                        dbInstance: dbUrl
                    };

                    try {
                        await Scoped.InstancesData[projectName].databaseRules(rulesObj, throwRateLimit('database'));
                        if (hasDisconnect) return;
                    } catch (e) {
                        if (hasDisconnect) return;
                        throw simplifyError('security_error', `${e}`);
                    }

                    const callSnapshot = async () => {
                        const data =
                            await (
                                isDocumentWatch
                                    ? readDocumentExtraction
                                    : queryDocumentExtraction
                            )(commands, projectName, dbName, dbUrl);
                        if (hasDisconnect) return;
                        const newHash = fnv64Hash(data);

                        if (newHash !== lastEmittedValue) {
                            const s = ugly ? await e2e_worker.encrypt(data, clientPublicKey, projectName) : data;
                            socket.emit('mSnapshot', [undefined, s]);
                        }
                        lastEmittedValue = newHash;
                    }

                    callSnapshot();
                    emission =
                        emitDatabase(commands.path, async () => {
                            try {
                                if (auth) await validateJWT(mtoken, projectName);
                                callSnapshot();
                            } catch (e) {
                                socket.emit('mSnapshot', [simplifyCaughtError(e), undefined]);
                            }
                        }, projectName, dbName, dbUrl);
                } catch (e) {
                    if (hasErrorLoger) console.error(`errRoute /${route} err:`, e);
                    socket.emit('mSnapshot', [simplifyCaughtError(e), undefined]);
                }
            } else if (route === _startDisconnectWriteTask) {
                if (taskWriter === false) return;
                try {

                    validateDbInstanceName(dbUrl);
                    checkRemoteDbName(dbName, allowDbNameFromRemoteClients);
                    if (residueError) throw residueError;

                    const { connectTask, disconnectTask } = commands;

                    validateLiveDbBody(reqBody, route);

                    socket.on('disconnect', async () => {
                        if (hasLogger) console.log(`/${route} unplugged, live for ${Date.now() - now}ms`);
                        if (taskWriter) taskWriter('_disconnectionTask', false);
                    });

                    taskWriter = async (endpoint, isConnected) => {
                        const taskData = isConnected ? connectTask : disconnectTask;
                        if (!taskData) return;
                        const auth =
                            mtoken
                                ? await validateJWT(mtoken, projectName).catch(() => null)
                                : undefined;

                        const rulesObj = {
                            headers: { ...headers },
                            ...auth ? { auth } : {},
                            endpoint,
                            prescription: basicClone(commands),
                            dbName,
                            dbUrl
                        };

                        await Scoped.InstancesData[projectName].databaseRules(rulesObj, throwRateLimit('database'));
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
}

function fnv64Hash(str) {
    if (typeof str !== 'string') {
        str = (Buffer.isBuffer(str) ? str : serialize(str)).toString('base64');
    }

    let hi = 0xcbf29ce4 | 0;
    let lo = 0x84222325 | 0;

    for (let i = 0; i < str.length; i++) {
        lo ^= str.charCodeAt(i);

        // Multiply by FNV prime: 0x00000100000001B3
        const low = lo >>> 0;
        const high = hi >>> 0;

        const product = low * 0x1b3;

        const newLo = product >>> 0;
        const carry = Math.floor(product / 0x100000000);

        hi = (high * 0x1b3 + low * 0x100 + carry) | 0;
        lo = newLo | 0;
    }

    return (
        (hi >>> 0).toString(16).padStart(8, '0') +
        (lo >>> 0).toString(16).padStart(8, '0')
    );
};