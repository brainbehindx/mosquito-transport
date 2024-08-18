import { Transform } from "stream";
import { BLOCKS_IDENTIFIERS, decryptData, DEFAULT_DELIMITER, one_mb } from "./utils";
import { MongoClient } from "mongodb";
import { mkdir } from "fs/promises";
import { join } from "path";
import { createWriteStream } from "fs";

const FILE_WATERMARK = one_mb * 100;

export const installBackup = (config, onInstallationStats) => {
    const { password, storage, onMongodbOption, delimiter } = { ...config };
    const stream = new Transform({});
    let buf, streamPromise;

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

    const DELIMITER = Buffer.from(delimiter || DEFAULT_DELIMITER, 'utf8');

    /**
     * @type {{[key: string]: MongoClient}}
     */
    const mongodbInstances = {};
    const dbUrlMap = {};

    const handleChunk = async (chunk) => {
        try {
            buf = buf ? Buffer.concat([buf, chunk]) : chunk;

            const stream_bit = desegmentBuffer(buf, DELIMITER);
            if (stream_bit) {
                const [bits, remainder] = stream_bit;
                buf = remainder;

                for (let bitIndex = 0; bitIndex < bits.length; bitIndex++) {
                    const elem = bits[bitIndex];

                    const handleBlocks = async (thisBits, index) => {
                        const thisElem = thisBits[index];
                        const thisHeader = !(index % 2) && Buffer.from(thisElem).toString('utf8');

                        if (thisHeader) {
                            lastBlocks.headers = thisHeader;
                        } else {
                            const BLOCK_ID = `${password ? (bitIndex + ':' + index) : index}`;
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
                                    const { url, ...dbOptions } = { ...onMongodbOption?.(dbUrl) };
                                    mongodbInstances[dbUrl] = new MongoClient(url || dbUrl, { ...dbOptions });
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
                    }

                    if (password) {
                        const [mainBits] = desegmentBuffer(decryptData(elem, password), DELIMITER);

                        for (let mainBitsIndex = 0; mainBitsIndex < mainBits.length; mainBitsIndex++) {
                            await handleBlocks(mainBits, mainBitsIndex);
                        }
                    } else await handleBlocks(bits, bitIndex);
                }
            }
        } catch (error) {
            stream.destroy(new Error(`${error}`));
            throw error;
        }
    }

    stream.on('data', chunk => {
        const thisPromise = streamPromise;
        const ended = stream.writableFinished;

        streamPromise = new Promise(async (resolve, reject) => {
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

/**
 * @type {( buf: Buffer ) => null | [Buffer, Buffer]}
 */
const desegmentBuffer = (buf, delimiter) => {
    let offset = 0, thisSegment;
    const blocks = [];

    while ((thisSegment = readVariableLength(buf, offset, delimiter)) !== null) {
        const { byteSize, nextOffset } = thisSegment;
        const binary = buf.subarray(offset += nextOffset, offset += byteSize);
        blocks.push(binary);
    }

    if (!blocks.length) return null;
    return [blocks, buf.subarray(offset, buf.length)];
}

// Function to read a variable-length integer with delimiter detection
function readVariableLength(buffer, offset, delimiter) {
    let length = 0;

    // Find the delimiter to identify the start of the length field
    const delimiterIndex = buffer.indexOf(delimiter, offset);
    if (delimiterIndex === -1 || delimiterIndex + delimiter.length >= buffer.length) {
        return null; // Delimiter not found or incomplete data
    }

    const lengthStart = delimiterIndex + delimiter.length;
    const remainingBytes = buffer.length - lengthStart;

    // Ensure there's enough data to read the length
    if (remainingBytes < 1) return null;

    // Determine the length based on the remaining bytes
    let byteCount = 0;
    while (byteCount < 8 && lengthStart + byteCount < buffer.length) {
        length = (length << 8) + buffer[lengthStart + byteCount];
        byteCount++;
        if (byteCount === remainingBytes) break;
    }

    return {
        byteSize: length,
        byteCount,
        nextOffset: lengthStart + byteCount
    };
}