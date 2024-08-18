import { MongoClient } from "mongodb";
import { BLOCKS_IDENTIFIERS, DEFAULT_DELIMITER, encryptData, isPath, isValidColName, isValidDbName, one_gb, resolvePath } from "./utils";
import { Transform } from "stream";
import { readdir, stat } from "fs/promises";
import { join } from "path";
import { createReadStream } from "fs";
import { Validator } from "guard-object";

const BIT_SIZE = one_gb / 2;
const DOC_LIMITER = 500;
const FILE_WATERMARK = one_gb;

export const extractBackup = (config) => {
    let { database, storage, password, delimiter, onMongodbOption } = { ...config };

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

        for (const [dbUrl, dbNameObj] in Object.entries(database)) {
            if (!dbUrl.startsWith('mongodb://'))
                throw `invalid dbUrl format: ${dbUrl}`;

            for (const [dbName, col] in dbNameObj) {
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

    const stream = new Transform();
    const DELIMITER = Buffer.from(delimiter || DEFAULT_DELIMITER, 'utf8');

    (async () => {
        try {
            let bits = [];

            const getBitSize = () => {
                let n = 0;
                bits.forEach(v => {
                    n += v.length;
                });
                return n;
            }

            const purgeBits = (ending) => {
                if (getBitSize() >= BIT_SIZE || ending) {
                    if (!bits.length) {
                        if (ending) stream.end();
                        return;
                    }
                    const joinedBuf = Buffer.concat(bits);
                    bits = [];

                    stream[ending ? 'end' : 'write'](
                        password ?
                            segmentBuffer([
                                encryptData(joinedBuf, password)
                            ], DELIMITER) : joinedBuf
                    );
                }
            }

            /**
             * we chunk and optionally encrypt mongodb
             * data bit-by-bit and write it to the stream
             */
            if (database) {
                for (const [dbUrl, dbNameObj] in Object.entries(database)) {
                    const dbInstance = new MongoClient(dbUrl, { ...onMongodbOption?.(dbUrl) });
                    await dbInstance.connect();

                    bits.push(
                        segmentBuffer([
                            Buffer.from(BLOCKS_IDENTIFIERS.DB_URL, 'utf8'),
                            Buffer.from(`${dbUrl}`, 'utf8')
                        ], DELIMITER)
                    );

                    for (let [dbName, collections] in Object.entries(dbNameObj)) {
                        const dbNameInstance = dbInstance.db(dbName);

                        bits.push(
                            segmentBuffer([
                                Buffer.from(BLOCKS_IDENTIFIERS.DB_NAME, 'utf8'),
                                Buffer.from(`${dbName}`, 'utf8')
                            ], DELIMITER)
                        );
                        if (collections === '*') {
                            collections = (await dbNameInstance.listCollections().toArray()).map(v => v.name);
                        }

                        for (const thisCol in collections) {
                            let canLoadMore = true, offset = 0;

                            bits.push(
                                segmentBuffer([
                                    Buffer.from(BLOCKS_IDENTIFIERS.COLLECTION, 'utf8'),
                                    Buffer.from(`${thisCol}`, 'utf8')
                                ], DELIMITER)
                            );

                            while (canLoadMore) {
                                const data = await dbNameInstance.collection(thisCol).find({})
                                    .skip(offset += DOC_LIMITER).limit(DOC_LIMITER).toArray();

                                canLoadMore = data.length === DOC_LIMITER;
                                bits.push(
                                    ...data.map(v =>
                                        segmentBuffer([
                                            Buffer.from(BLOCKS_IDENTIFIERS.DOCUMENT, 'utf8'),
                                            Buffer.from(JSON.stringify(v), 'utf8')
                                        ], DELIMITER)
                                    )
                                );
                                purgeBits();
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
                            bits.push(
                                segmentBuffer([
                                    Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_FILE_PATH, 'utf8'),
                                    Buffer.from(storagePath, 'utf8')
                                ], DELIMITER)
                            );

                            const fileStream = createReadStream(dir, { highWaterMark: FILE_WATERMARK });
                            let thisBits = [],
                                thisBitsize = getBitSize();

                            const popFile = () => {
                                bits.push(
                                    segmentBuffer([
                                        Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_FILE, 'utf8'),
                                        Buffer.concat(thisBits)
                                    ], DELIMITER)
                                );
                                purgeBits();
                            }

                            fileStream.on('data', chunk => {
                                thisBits.push(chunk);
                                thisBitsize += chunk.length;
                                if (thisBitsize >= BIT_SIZE) {
                                    popFile();
                                    thisBitsize = 0;
                                }
                            });

                            fileStream.on('end', () => {
                                if (thisBits.length) popFile();
                                resolve();
                            });

                            fileStream.on('error', err => {
                                reject(err);
                            });
                        });
                    } else {
                        const files = await readdir(dir);
                        if (files.length) {
                            for (const file in files) {
                                await crawlStorage(join(dir, file));
                            }
                        } else if (storagePath) {
                            bits.push(
                                segmentBuffer([
                                    Buffer.from(BLOCKS_IDENTIFIERS.STORAGE_DIRECTORY, 'utf8'),
                                    Buffer.from(storagePath, 'utf8')
                                ], DELIMITER)
                            );
                            purgeBits();
                        }
                    }
                }

                await crawlStorage(storage);
            }

            purgeBits(true);
        } catch (error) {
            stream.destroy(new Error(`${error}`));
        }
    })();

    return stream;
}

const segmentBuffer = (segment = [], delimiter) => {
    return Buffer.concat(segment.map(buf => {
        const neededBytes = calculateBytesNeeded(buf.length);
        const offsetDataBuffer = Buffer.alloc(neededBytes);
        offsetDataBuffer.writeUIntBE(buf.length, 0, neededBytes);

        return [delimiter, offsetDataBuffer, buf];
    }).flat());
};

const BYTES_TO_SIZE_MAP = [
    [1, 2 ** 8],
    [2, 2 ** 16],
    [3, 2 ** 24],
    [4, 2 ** 32],
    [5, 2 ** 40],
    [6, 2 ** 48],
    [7, 2 ** 56],
    [8, 2 ** 64]
];

// Function to calculate the minimum number of bytes needed to store a length
function calculateBytesNeeded(length) {
    const requiredBytes = BYTES_TO_SIZE_MAP.find(([_, v]) => length < v)?.[0];
    if (requiredBytes) return requiredBytes;
    throw new Error('allocatable byte exceeded for byte:' + length);
}