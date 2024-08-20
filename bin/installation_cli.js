#!/usr/bin/env node

import { join, resolve } from 'path';
import { BIN_CONFIG_FILE, isHttp_s, isPath, one_gb, resolvePath } from './utils.js';
import { guardArray, GuardSignal, niceGuard, Validator } from 'guard-object';
import { createReadStream } from 'fs';
import fetch from 'node-fetch';
import { installBackup } from './install_backup.js';

const commands = process.argv.slice(2).map(v => v.trim()).filter(v => v);

console.log('args:', commands);

let config;

if (!commands.length) {
    try {
        config = require(join(process.cwd(), BIN_CONFIG_FILE)).install;
    } catch (error) { }
} else if (
    commands.length === 1 &&
    isPath(commands[0])
) {
    config = require(resolvePath(commands[0])).install;
} else {
    const fields = ['password', 'storage', 'source'];

    config = Object.fromEntries(
        commands.map(v => {
            const key = fields.find(n => v.startsWith(`${n}=`));
            if (key) return [key, v.substring(key.length + 1)];
            return [v];
        }).filter(v => v)
    );
}

const {
    password,
    storage,
    source,
    sourceHeader,
    onMongodbOption,
    ...restConfig
} = config;

const newConfig = {
    password,
    storage,
    onMongodbOption
};

let sourcePath;

if (source === undefined) {
    sourcePath = resolve(process.cwd(), 'mosquito_backup.bin');
} else if (
    isPath(source) ||
    Validator.HTTPS(source) ||
    Validator.HTTP(source)
) {
    sourcePath = isPath(source) ? resolvePath(source) : source;
    if (isHttp_s(source)) {
        if (
            sourceHeader !== undefined &&
            (!Validator.OBJECT(sourceHeader) ||
                !niceGuard(guardArray(GuardSignal.STRING), Object.values(sourceHeader)))
        ) throw '"sourceHeader" should be a way object as { field_key: string } ';
    } else if (sourceHeader !== undefined)
        throw '"sourceHeader" should only be provided when "source" is an http link';
} else throw `expected "source" as a file path or http link but got ${source}`;

const unknownFields = Object.keys(restConfig);

if (unknownFields.length)
    throw `unknown fields: ${unknownFields}`;

let sourceStream;

try {
    if (isHttp_s(sourcePath)) {
        const remoteStream = await fetch(sourcePath, { headers: { ...sourceHeader } });
        sourceStream = remoteStream.body;
        console.log('backup server status:', remoteStream.statusText || remoteStream.status);
    } else {
        sourceStream = createReadStream(sourcePath, { highWaterMark: one_gb });
    }
    newConfig.stream = sourceStream;

    const stats = await installBackup(newConfig);
    console.log('installation stats:\n', stats);
    console.log('installation completed ✅');
    process.exit(0);
} catch (error) {
    console.error(error);
    process.exit(1);
}