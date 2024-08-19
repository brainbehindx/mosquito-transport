import { BLOCKS_IDENTIFIERS, decryptData, one_gb } from "./utils";
import { MongoClient } from "mongodb";
import { mkdir } from "fs/promises";
import { join } from "path";
import { createWriteStream } from "fs";
import { ReadableBit } from "@deflexable/bit-stream";

const FILE_WATERMARK = one_gb * .3;

export const installBackup = (config, onInstallationStats) => {
    const { password, storage, onMongodbOption } = { ...config };
    const stream = new ReadableBit();
    let steadyPromise;

    const INIT_BLOCKS = {
        database: {
            dbUrl: undefined,
            dbName: undefined,
            collection: undefined
        },
        storage: {
            path: undefined,
            file: undefined
        },
        headers: undefined
    };
    const lastBlocks = {
        ...INIT_BLOCKS
    };

    const installionStats = {
        database: {},
        totalWrittenDocuments: 0,
        totalWrittenFiles: 0
    };

    /**
     * @type {{[key: string]: MongoClient}}
     */
    const mongodbInstances = {};
    const dbUrlMap = {};
    let bitIndex = 0;

    const handleChunk = async (chunk) => {
        try {
            const thisElem = password ? decryptData(chunk, password) : chunk;
            const thisHeader = !(bitIndex++ % 2) && Buffer.from(thisElem).toString('utf8');

            if (thisHeader) {
                lastBlocks.headers = thisHeader;
            } else {
                const BLOCK_ID = `${bitIndex}`;
                if (lastBlocks.headers === undefined)
                    throw `no blocks identifier at block_id (${BLOCK_ID})`;
                const prevHeader = lastBlocks.headers;

                if (prevHeader === BLOCKS_IDENTIFIERS.DB_URL) {
                    lastBlocks.database = { dbUrl: Buffer.from(thisElem).toString('utf8') };
                    if (lastBlocks.storage.path)
                        throw `(${BLOCKS_IDENTIFIERS.DB_URL}) block should come first before (${BLOCKS_IDENTIFIERS.STORAGE_FILE_PATH})`;
                } else if (prevHeader === BLOCKS_IDENTIFIERS.DB_NAME) {
                    lastBlocks.database.dbName = Buffer.from(thisElem).toString('utf8');
                } else if (prevHeader === BLOCKS_IDENTIFIERS.COLLECTION) {
                    lastBlocks.database.collection = Buffer.from(thisElem).toString('utf8');
                } else if (prevHeader === BLOCKS_IDENTIFIERS.DOCUMENT) {
                    const { collection, dbName, dbUrl } = lastBlocks.database;
                    if (typeof dbUrl !== 'string' || !dbUrl.trim())
                        throw `no previous ${BLOCKS_IDENTIFIERS.DB_URL} was registered at block_id ${BLOCK_ID}`;
                    if (typeof dbName !== 'string' || !dbName.trim())
                        throw `no previous ${BLOCKS_IDENTIFIERS.DB_NAME} was registered at block_id ${BLOCK_ID}`;
                    if (typeof collection !== 'string' || !collection.trim())
                        throw `no previous ${BLOCKS_IDENTIFIERS.COLLECTION} was registered at block_id ${BLOCK_ID}`;

                    if (!mongodbInstances[dbUrl]) {
                        const mongoHandle = onMongodbOption?.(dbUrl);
                        const isInstance = mongoHandle instanceof MongoClient;

                        const { url, ...dbOptions } = isInstance ? {} : { ...mongoHandle };

                        mongodbInstances[dbUrl] = isInstance ? mongoHandle : new MongoClient(url || dbUrl, { ...dbOptions });
                        dbUrlMap[dbUrl] = url || dbUrl;
                        installionStats.database[url || dbUrl] = {};
                    }
                    const thisUrl = dbUrlMap[dbUrl];

                    if (installionStats.database[thisUrl][dbName]) {
                        ++installionStats.database[thisUrl][dbName];
                    } else installionStats.database[thisUrl][dbName] = 1;

                    const { _id, ...docRest } = JSON.parse(Buffer.from(thisElem).toString('base64'));

                    if (!_id) throw `invalid doc found in block_id ${BLOCK_ID}`;
                    await mongodbInstances[dbUrl].db(dbName).collection(collection).replaceOne(
                        { _id },
                        { ...docRest },
                        { upsert: true }
                    );
                    ++installionStats.totalWrittenDocuments;
                } else {
                    lastBlocks.database = INIT_BLOCKS.database;

                    if (prevHeader === BLOCKS_IDENTIFIERS.STORAGE_DIRECTORY) {
                        const path = Buffer.from(thisElem).toString('utf8');
                        lastBlocks.storage = INIT_BLOCKS.storage;
                        try {
                            await mkdir(join(storage, path), {
                                force: true,
                                recursive: true
                            });
                        } catch (_) { }
                    } else if (prevHeader === BLOCKS_IDENTIFIERS.STORAGE_FILE_PATH) {
                        const path = join(storage, Buffer.from(thisElem).toString('utf8'));
                        if (lastBlocks.storage.file) {
                            lastBlocks.storage.file.end();
                        }
                        lastBlocks.storage = { path };
                    } else if (prevHeader === BLOCKS_IDENTIFIERS.STORAGE_FILE) {
                        if (typeof lastBlocks.storage.path !== 'string')
                            throw `no previous ${BLOCKS_IDENTIFIERS.STORAGE_FILE_PATH} was registered at block_id ${BLOCK_ID}`;

                        if (lastBlocks.storage.file) {
                            lastBlocks.storage.file.write(thisElem);
                        } else {
                            const writeStream = createWriteStream(lastBlocks.storage.path, {
                                highWaterMark: FILE_WATERMARK
                            });
                            writeStream.write(thisElem);
                            lastBlocks.storage.file = writeStream;
                            ++installionStats.totalWrittenFiles;
                        };
                    } else throw `unknown block identifier "${prevHeader}" at block_id ${BLOCK_ID}`;
                }
                lastBlocks.headers = undefined;
            }
        } catch (error) {
            stream.destroy(new Error(`${error}`));
            throw error;
        }
    }

    stream.on('data', chunk => {
        const thisPromise = steadyPromise;
        const ended = stream.writableFinished;

        steadyPromise = new Promise(async (resolve, reject) => {
            try {
                await thisPromise;
                await handleChunk(chunk);
                resolve();
                if (ended && lastBlocks.storage.file) {
                    lastBlocks.storage.file.end();
                    lastBlocks.storage.file = undefined;
                }
            } catch (error) {
                reject(error);
            }
        });
    });

    stream.on('end', () => {
        onInstallationStats?.(installionStats);
    });

    stream.on('error', () => {
        if (lastBlocks.storage.file) {
            lastBlocks.storage.file.end();
            lastBlocks.storage.file = undefined;
        }
    });

    return stream;
}