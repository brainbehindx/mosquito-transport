import { MongoClient } from "mongodb";
import { BLOCKS_IDENTIFIERS, encryptData, isPath, isValidColName, isValidDbName, one_gb, resolvePath } from "./utils.js";
import { readdir, stat } from "fs/promises";
import { createReadStream } from "fs";
import { Validator } from "guard-object";
import { WritableBit } from "@deflexable/bit-stream";
import { join } from "path";

const BIT_SIZE = one_gb * .2;
const DOC_LIMITER = 500;

export const extractBackup = (config) => {
    let { database, storage, password, onMongodbOption } = { ...config };

    if (password !== undefined && !Validator.TRIMMED_NON_EMPTY_STRING(password))
        throw `expected "password" as non-empty string but got ${password}`;

    if (onMongodbOption !== undefined && typeof onMongodbOption !== 'function')
        throw `expected "onMongodbOption" to be function but got: ${onMongodbOption}`;

    if (isPath(storage)) {
        storage = resolvePath(storage);
    } else if (storage !== undefined)
        throw `expected "storage" as an absolute or relative file path but got ${storage}`;

    if (database !== undefined && !Validator.OBJECT(database)) {
        throw `expected "database" to be an object but got ${database}`;
    } else if (database) {

        for (const [dbUrl, dbNameObj] of Object.entries(database)) {
            if (!dbUrl.startsWith('mongodb://'))
                throw `invalid dbUrl format: ${dbUrl}`;

            for (const [dbName, col] of Object.entries(dbNameObj)) {
                if (!isValidDbName(dbName))
                    throw `invalid dbName: "${dbName}"`;

                if (col !== '*') {
                    if (Array.isArray(col)) {
                        col.forEach(r => {
                            if (!isValidColName(r))
                                throw `invalid collection named: ${r}`;
                        });
                    } else throw `collection should be either "*" or Array<string> but got ${col}`;
                }
            }
        }
    }

    const stream = new WritableBit();

    (async () => {
        try {
            const pushBuffer = (buf) => {
                stream.write(
                    password ? encryptData(buf, password) : buf
                );
            }

            /**
             * we chunk and optionally encrypt mongodb
             * data bit-by-bit and write it to the stream
             */
            if (database) {
                for (const [dbUrl, dbNameObj] of Object.entries(database)) {
                    const mongoHandle = onMongodbOption?.(dbUrl);
                    const isInstance = mongoHandle instanceof MongoClient;

                    const dbInstance = isInstance ? mongoHandle : new MongoClient(dbUrl, { ...mongoHandle });
                    await dbInstance.connect();

                    pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.DB_URL, 'utf8'));
                    pushBuffer(Buffer.from(`${dbUrl}`, 'utf8'));

                    for (let [dbName, collections] of Object.entries(dbNameObj)) {
                        const dbNameInstance = dbInstance.db(dbName);

                        pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.DB_NAME, 'utf8'));
                        pushBuffer(Buffer.from(`${dbName}`, 'utf8'));

                        if (collections === '*') {
                            collections = (await dbNameInstance.listCollections().toArray()).map(v => v.name);
                        }

                        for (const thisCol of collections) {
                            let canLoadMore = true, offset = 0;

                            pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.COLLECTION, 'utf8'));
                            pushBuffer(Buffer.from(`${thisCol}`, 'utf8'));

                            while (canLoadMore) {
                                const data = await dbNameInstance.collection(thisCol).find({})
                                    .skip(offset).limit(DOC_LIMITER).toArray();
                                offset += DOC_LIMITER;
                                canLoadMore = data.length === DOC_LIMITER;
                                data.forEach(v => {
                                    pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.DOCUMENT, 'utf8'));
                                    pushBuffer(Buffer.from(JSON.stringify(v), 'utf8'))
                                });
                            }
                        }
                    }
                }
            }

            /**
             * if storage is enabled we recursively read
             * the entire storage directory and optionally
             * encrypt the data bit-by-bit and write it to
             * the stream
             */
            if (storage) {
                const crawlStorage = async (dir = '') => {
                    const storagePath = dir.substring(storage.length);

                    if ((await stat(dir)).isFile()) {

                        await new Promise((resolve, reject) => {
                            pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_FILE_PATH, 'utf8'));
                            pushBuffer(Buffer.from(storagePath, 'utf8'));

                            const fileStream = createReadStream(dir);
                            let thisBits = [],
                                thisBitsize = 0;

                            const popFile = () => {
                                if (thisBits.length) {
                                    pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_FILE, 'utf8'));
                                    pushBuffer(Buffer.concat(thisBits));
                                }
                                thisBitsize = 0;
                                thisBits = [];
                            }

                            fileStream.on('data', chunk => {
                                thisBits.push(chunk);
                                if (thisBitsize += chunk.length >= BIT_SIZE) {
                                    popFile();
                                }
                            });

                            fileStream.on('end', () => {
                                popFile();
                                resolve();
                            });

                            fileStream.on('error', err => {
                                reject(err);
                            });
                        });
                    } else {
                        const files = await readdir(dir);
                        if (files.length) {
                            for (const file of files) {
                                await crawlStorage(join(dir, file));
                            }
                        } else if (storagePath) {
                            pushBuffer(Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_DIRECTORY, 'utf8'));
                            pushBuffer(Buffer.from(storagePath, 'utf8'));
                        }
                    }
                }

                await crawlStorage(storage);
            }

            stream.end();
        } catch (error) {
            stream.destroy(new Error(`${error}`));
        }
    })();

    return stream;
};