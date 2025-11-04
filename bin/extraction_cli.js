#!/usr/bin/env node

import { join, resolve } from 'path';
import { BIN_CONFIG_FILE, isHttp_s, isPath, one_gb, RESERVED_DB, resolvePath } from './utils.js';
import { extractBackup } from './extract_backup.js';
import { guardArray, guardObject, GuardSignal, niceGuard, Validator } from 'guard-object';
import { MongoClient } from 'mongodb';
import { createWriteStream } from 'fs';
import fetch from 'node-fetch';

const commands = process.argv.slice(2).map(v => v.trim()).filter(v => v);
let config;
const startTime = Date.now();

if (!commands.length) {
    try {
        config = (await import(`${join(process.cwd(), BIN_CONFIG_FILE)}`)).extract;
    } catch (error) {
        config = {
            dbName: '$'
        };
    }
} else if (
    commands.length === 1 &&
    isPath(commands[0])
) {
    config = (await import(`${resolvePath(commands[0])}`)).extract;
} else {
    const fields = ['password', 'storage', 'dest', 'dbName'];

    config = Object.fromEntries(
        commands.map(v => {
            const key = fields.find(n => v.startsWith(`${n}=`));
            if (key) return [key, v.substring(key.length + 1)];
            return [v];
        }).filter(v => v)
    );
}

if (!config) throw 'you need to export "extract" in your backup config file';

const {
    password,
    storage,
    dest,
    destHeaders,
    dbName,
    database,
    onMongodbOption,
    ...restConfig
} = config;

const newConfig = {
    password,
    storage,
    onMongodbOption
};
let destination;

if (dest === undefined) {
    destination = resolve(process.cwd(), 'mosquito_backup.bin');
} else if (
    isPath(dest) ||
    Validator.HTTPS(dest) ||
    Validator.HTTP(dest)
) {
    destination = isPath(dest) ? resolvePath(dest) : dest;
    if (isHttp_s(dest)) {
        if (
            destHeaders !== undefined &&
            (!Validator.OBJECT(destHeaders) ||
                !niceGuard(guardArray(GuardSignal.STRING), Object.values(destHeaders)))
        ) throw '"destHeaders" should be a way object as { field_key: string } ';
    } else if (destHeaders !== undefined)
        throw '"destHeaders" should only be provided when "dest" is an http link';
} else throw `expected "dest" as a file path or http link but got ${dest}`;

if (
    (dbName !== undefined && database !== undefined)
) throw 'you can only one of "dbName" or "database" but not both';

if (dbName) {
    let thisDbList;
    if (typeof dbName !== 'string')
        throw `expected "dbName" to be a string but got ${typeof dbName}`;
    if (dbName === '$') {
        const client = new MongoClient('mongodb://localhost:27017');
        await client.connect();
        const dbList = (await client.db().admin().listDatabases())
            .databases.map(v => v.name).filter(v => !RESERVED_DB.includes(v));

        thisDbList = dbList;
    } else thisDbList = dbName.split('/');

    guardObject(
        guardArray(GuardSignal.TRIMMED_NON_EMPTY_STRING)
    ).validate(thisDbList);
    if (thisDbList.length)
        newConfig.database = {
            'mongodb://localhost:27017': Object.fromEntries(
                thisDbList.map(v => [v, '*'])
            )
        };
} else if (database) {
    newConfig.database = database;
};

const unknownFields = Object.keys(restConfig);

if (unknownFields.length)
    throw `unknown fields: ${unknownFields}`;

const stream = extractBackup(newConfig);

stream.on('end', () => {
    console.log(`backup written to ${destination}`);
    console.log(`process took ${Date.now() - startTime}ms`);
    process.exit(0);
});

stream.on('error', err => {
    console.error(err);
    process.exit(1);
});

if (isHttp_s(destination)) {
    const remoteStream = await fetch(destination, {
        headers: { ...destHeaders },
        body: stream
    });
    const serverResponse = await remoteStream.text();

    console.log(`backup server response: ${serverResponse}`);
} else {
    const fileStream = createWriteStream(destination, { highWaterMark: one_gb });
    stream.pipe(fileStream);
}