import { join, resolve } from 'path';
import { BIN_CONFIG_FILE, isPath, one_gb, resolvePath } from './utils';
import { guardArray, GuardSignal, niceGuard, Validator } from 'guard-object';
import { createReadStream } from 'fs';
import fetch from 'node-fetch';
import { installBackup } from './install_backup';

const args = process.argv.join(' ');
const commands = args.split(' ').filter(v => v);

let config;

if (args === 'install_mosquito_backup') {
    try {
        config = require(join(process.cwd(), BIN_CONFIG_FILE)).install;
    } catch (error) {
        config = {
            dbName: '$'
        };
    }
} else if (
    commands[0] === 'install_mosquito_backup' &&
    commands.length === 2 &&
    isPath(commands[1])
) {
    config = require(resolvePath(commands[1])).install;
} else {
    const fields = ['password', 'storage', 'source'];

    config = Object.fromEntries(
        commands.map(v => {
            const key = fields.find(n => v.startsWith(`${n}=`));
            if (key) return [key, v.substring(key.length + 1)];
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
    if (source.startsWith('http')) {
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

const installationStream = installBackup(newConfig, stats => {
    console.log('installation stats:\n', stats);
});

installationStream.on('end', () => {
    console.log('installation completed ✅');
});

installationStream.on('error', err => {
    console.error(err);
    process.exit(1);
});

if (source.startsWith('http')) {
    const remoteStream = await fetch(sourcePath, { headers: { ...sourceHeader } });
    remoteStream.body.pipe(installationStream);
    console.log('backup server status:', remoteStream.statusText || remoteStream.status);
} else {
    const sourceStream = createReadStream(sourcePath, { highWaterMark: one_gb });
    sourceStream.pipe(installationStream);
}