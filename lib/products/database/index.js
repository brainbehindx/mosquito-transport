import express from "express";
import { Timestamp } from "mongodb";
import { niceTry, queryEntries, simplifyError } from "../../helpers/utils.js";
import { getDB } from "./base.js";
import _ from 'lodash';
import { verifyJWT } from "../auth/tokenizer.js";
import { Scoped } from "../../helpers/variables.js";

export const TIMESTAMP = { $type: "timestamp" };

export const writeDocument = async (commands, projectName, dbName, dbUrl) => {
    if (commands.scope === 'update' && !commands.liveExist && !(await readDocument({ path: commands.path, find: commands.find }, projectName, dbName, dbUrl)))
        throw simplifyError('document_not_found', 'You cannot update document that does not exist');

    const scope = commands.scope || 'set',
        k = getDB(projectName, dbName, dbUrl).collection(commands.path),
        deserializedValue = deserializeWriteValue(commands.value),
        g = await (
            scope === 'delete' ?
                k.deleteOne({ ...commands.find })
                :
                scope === 'set' ? k.insertOne({ ...deserializedValue }) :
                    (scope === 'update' || scope === 'merge') ? k.updateOne({ ...commands.find }, { $set: { ...deserializedValue } }, { upsert: scope === 'merge' }) :
                        scope === 'setMany' ? k.insertMany({ ...deserializedValue }) :
                            (scope === 'updateMany' || scope === 'mergeMany') ? k.updateMany({ ...commands.find }, { $set: { ...deserializedValue } }, { upsert: scope === 'merge' })
                                :
                                k.replaceOne(h, { ...commands.value })
        );

    return g.acknowledged;
}

const deserializeWriteValue = (value) => {
    if (!value) return value;

    const result = {},
        unset = {};

    queryEntries(value).forEach(([key, value]) => {
        const l = key.split('.').filter((_, i, a) => i !== a.length);

        if (key.endsWith('$timestamp')) {
            _.set(result, `${l.map((v, i, a) => i === a.length - 1 ? `$currentDate.${v}` : v).join('.')}`, value === 'now' ? { $type: 'timestamp' } : Timestamp.fromNumber(value));
        } else if (key.endsWith('$increment')) {
            _.set(result, `${l.map((v, i, a) => i === a.length - 1 ? `$inc.${v}` : v).join('.')}`, value || 1);
        } else if (key.endsWith('$deletion')) {
            _.set(unset, `${l.join('.')}`, value);
        } else _.set(result, key, value);
    });

    if (Object.keys(unset).length) result['$unset'] = unset;
    return result;
}

export const readDocument = async (commands, projectName, dbName, dbUrl) => {
    const d = (await getDB(projectName, dbName, dbUrl).collection(commands.path || '').findOne({ ...commands.find }));

    return await extractDocField(d, commands);
}

export const queryDocument = async (commands, projectName, dbName, dbUrl) => {
    const d = await getDB(projectName, dbName, dbUrl).collection(commands.path).find({ ...commands.find }).toArray();

    return Promise.all(d.map(v => extractDocField(v, commands, dbName, dbUrl)));
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

export const databaseRoutes = (projectName) => [
    '_readDocument',
    '_writeDocument',
    '_queryCollection',
    '_writeMapDocument'
].map(route =>
    express.Router({ caseSensitive: true })[
        (route == '_writeDocument' || route === '_writeMapDocument') ? 'post' : 'get'
    ](`/${route}`, async (req, res) => {
        try {
            const { commands, dbName, dbUrl, authToken } = req.body,
                operation = route === '_readDocument' ? 'findOne' : route === '_queryCollection' ? 'findMany' : route === '_writeDocument' ? (commands.scope || 'set') : route === '_writeMapDocument' ? 'batchWrite' : 'unknown',
                auth = await niceTry(() => verifyJWT(authToken, this.projectName));

            const rulesObj = {
                ...(auth ? { auth: { ...auth, token: authToken } } : {}),
                collection: commands.path || '',
                operation,
                find: commands.find,
                value: commands.value,
                ...(operation === 'batchWrite' ? { batchWrite: commands.list } : {})
            };

            try {
                await Scoped.DatabaseRules[projectName]?.(rulesObj);
            } catch (e) {
                throw simplifyError('security_error', `${e}`);
            }

            switch (route) {
                case '_readDocument':
                    const result = await readDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', result });
                    break;
                case '_writeDocument':
                    const committed = await writeDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', committed });
                    break;
                case '_queryCollection':
                    const result1 = await queryDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', result: result1 });
                    break;
                case '_writeMapDocument':
                    const committed1 = await writeMapDocument(commands, projectName, dbName, dbUrl);
                    res.status(200).send({ status: 'success', committed: committed1 });
                    break;
            }
        } catch (e) {
            res.status(403).send({ status: 'error', ...(e.simpleError ? e : simplifyError('unexpected_error', `${e}`)) });
        }
    })
);