import { join } from "path";
import { STORAGE_DIRS } from "../../helpers/values";
import { access, appendFile, constants, open, readdir, readFile, rename, rm, stat, unlink, writeFile } from 'fs/promises';
import { createHash } from "crypto";
import { PassThrough } from "stream";
import { Scoped } from "../../helpers/variables";
import { createReadStream, createWriteStream } from "fs";
import { availableMemory } from "process";
import { ensureDir, normalizeRoute } from "../../helpers/utils";

export const getSource = async (path, projectName) => {
    path = strapPath(path);
    const { FILES, HASH_LINK, HASH_FILE } = STORAGE_DIRS(projectName);

    const [mainPath, hashPath] = await Promise.all([
        fileExists(join(FILES, path)),
        fileExists(join(HASH_LINK, path))
    ]);

    if (mainPath) return { source: mainPath };

    if (hashPath) {
        try {
            const hashValue = await readFile(hashPath, 'utf8');
            return { source: join(HASH_FILE, hashValue), hashValue };
        } catch (error) { console.error(error); }
    }

    return {};
};

export const streamWritableSource = (path, makeHash, projectName, callback) => {
    path = strapPath(path);
    const stream = new PassThrough();

    const start = () => new Promise(async (resolve, reject) => {
        let writeReadyCallback;
        const writeReadyPromise = new Promise((resolve, reject) => {
            writeReadyCallback = err => {
                if (err) reject();
                else resolve();
            };
        });

        try {
            const { HASH_FILE, FILES, HASH_GROUPING, HASH_LINK, PENDING_HASH_LOG } = STORAGE_DIRS(projectName);

            if (makeHash) {
                const thisSource = getSource(path, projectName);
                const sessionID = `${Date.now()}${++Scoped.AbsoluteIterator}`;

                const removeLogFlag = async (deleteStage) => {
                    try {
                        if (deleteStage) await unlink(fileWriter.path);
                    } catch (error) {
                        console.error(error);
                        setTimeout(() => {
                            unlink(fileWriter.path);
                        }, 500);
                    }

                    const handler = await openIO(PENDING_HASH_LOG);
                    try {
                        const logValue = (await handler.read('utf8')).split('\n').filter(v => v !== sessionID && v).join('\n').trim();
                        await handler.write(logValue, 'utf8');
                    } catch (error) {
                        console.error(error);
                    }
                    await handler.close();
                };
                /** @type {import('fs').WriteStream} */
                let fileWriter,
                    bufferSize = 0,
                    residueExecutions = [];

                const hasher = createHash('sha256');

                stream.on('data', chunk => {
                    const execute = () => {
                        fileWriter.write(chunk);
                        hasher.update(chunk);
                        bufferSize += chunk.length;
                    }
                    if (residueExecutions) {
                        residueExecutions.push(execute);
                    } else execute();
                });

                stream.on('error', async err => {
                    await writeReadyPromise;
                    reject(err);
                    removeLogFlag(true);
                });

                stream.on('end', async () => {
                    await writeReadyPromise;

                    try {
                        fileWriter.end();
                        const { hashValue } = await thisSource;
                        const hashResult = encodeURIComponent(hasher.digest().toString('base64'));
                        const hashPath = join(HASH_FILE, hashResult);

                        const saveHash = async () => {
                            await Promise.all([
                                writeFile(await ensureDir(join(HASH_LINK, path)), hashResult, 'utf8'),
                                openIO(await ensureDir(join(HASH_GROUPING, hashResult))).then(async handler => {
                                    try {
                                        const newList = [
                                            ...new Set([
                                                ...(await handler.read('utf8')).split('\n'),
                                                encodeURIComponent(path)
                                            ])
                                        ].filter(v => v).join('\n');

                                        await handler.write(newList, 'utf8');
                                    } catch (error) { console.error(error); }
                                    handler.close();
                                })
                            ]);
                        };

                        if (await fileExists(hashPath)) {
                            let uri;
                            if (hashResult !== hashValue) {
                                uri = await new Promise(async (resolve, reject) => {
                                    try {
                                        let bufferOffset = 0;
                                        let wasSame = true;
                                        let writtenPath;

                                        while (bufferOffset < bufferSize) {
                                            // avoid overflowing the system's memory
                                            const BUFFERING_LIMIT = Math.round(availableMemory() / 3);

                                            const readSize = Math.min(BUFFERING_LIMIT, bufferSize - bufferOffset);
                                            const [incomingFile, restedFile] = await Promise.all([
                                                readFileSection(fileWriter.path, bufferOffset, bufferOffset + readSize),
                                                readFileSection(hashPath, bufferOffset, bufferOffset + readSize)
                                            ]);

                                            if (!incomingFile.equals(restedFile)) {
                                                wasSame = false;
                                                await new Promise(async (resolve, reject) => {
                                                    const writer = createWriteStream(await ensureDir(join(FILES, path)));
                                                    writtenPath = writer.path;
                                                    createReadStream(fileWriter.path)
                                                        .pipe(writer)
                                                        .on('finish', resolve)
                                                        .on('error', reject);
                                                });
                                                break;
                                            }
                                            bufferOffset += readSize;
                                        }
                                        try {
                                            await deleteSource(path, projectName, wasSame ? 'main' : 'hash');
                                        } catch (_) { }
                                        if (wasSame) await saveHash();
                                        resolve(wasSame ? hashPath : writtenPath);
                                    } catch (error) {
                                        reject(error);
                                    }
                                });
                            } else uri = hashPath;
                            await removeLogFlag(true);
                            resolve(uri);
                        } else {
                            try {
                                await deleteSource(path, projectName);
                            } catch (_) { }
                            await rename(fileWriter.path, hashPath);
                            await saveHash();
                            await removeLogFlag();
                            resolve(hashPath);
                        }
                    } catch (error) {
                        await removeLogFlag(true);
                        reject(error);
                    }
                });
                await openIO(await ensureDir(PENDING_HASH_LOG)).then(async handler => {
                    try {
                        await handler.append(`\n${sessionID}`, 'utf8');
                    } catch (error) { console.error(error); }
                    await handler.close();
                });
                fileWriter = createWriteStream(await ensureDir(join(HASH_FILE, sessionID)));
                residueExecutions.forEach(e => e());
                residueExecutions = undefined;
                writeReadyCallback();
            } else {
                let writable, residueBuffers = [];

                stream.on('data', buf => {
                    if (residueBuffers) residueBuffers.push(buf);
                    else writable.write(buf);
                });
                stream.on('error', reject);
                stream.on('end', async () => {
                    await writeReadyPromise;
                    try {
                        await deleteSource(path, projectName, 'hash');
                    } catch (_) { }
                    resolve(writable.path);
                });
                writable = createWriteStream(await ensureDir(join(FILES, path)));
                residueBuffers.forEach(buf => {
                    writable.write(buf);
                });
                residueBuffers = undefined;
                writeReadyCallback();
            }
        } catch (error) {
            reject(error);
            writeReadyCallback(error || new Error(''));
        }
    });

    start().then(uri => {
        callback(undefined, uri);
    }).catch(err => {
        callback(err);
        stream.destroy(err);
    });

    return stream;
};

export const streamReadableSource = (path, projectName) => {
    path = strapPath(path);
    const stream = new PassThrough();

    getSource(path, projectName).then(result => {
        if (result?.source) {
            createReadStream(result.source).pipe(stream);
        } else {
            stream.destroy(new Error(`ENOENT: no such file or directory, open '${path}'`));
        }
    });

    return stream;
};

export const deleteDir = async (path, projectName) => {
    path = strapPath(path);
    const { FILES, HASH_LINK } = STORAGE_DIRS(projectName);

    const [mainDeletion, hashDeletion] = await Promise.all(
        [FILES, HASH_LINK].map(async (dir, isHash) => {
            dir = join(dir, path);
            try {
                if (isHash) {
                    const recursiveDeletion = async (dir, trailingPath) => {
                        const fileListing = await readdir(dir);
                        await Promise.allSettled(
                            fileListing.map(async p => {
                                const thisPath = join(dir, p);
                                const dest = join(trailingPath, p);

                                if ((await stat(thisPath)).isDirectory()) {
                                    await recursiveDeletion(thisPath, dest);
                                } else await deleteSource(dest, projectName, 'hash');
                            })
                        );
                    }
                    await recursiveDeletion(dir, path);
                }

                await rm(dir, { recursive: true, force: true });
            } catch (error) {
                return error;
            }
        })
    );
    if (hashDeletion && mainDeletion)
        throw mainDeletion;
};

export const deleteSource = async (path, projectName, deletion) => {
    path = strapPath(path);
    const { FILES, HASH_LINK, HASH_FILE, HASH_GROUPING } = STORAGE_DIRS(projectName);

    const [mainDeletion, hashDeletion] = await Promise.all([
        (async () => {
            try {
                if (![undefined, 'main'].includes(deletion)) return;
                await unlink(join(FILES, path));
            } catch (error) {
                return error;
            }
        })(),
        (async () => {
            try {
                if (![undefined, 'hash'].includes(deletion)) return;
                const hashPath = join(HASH_LINK, path);
                const hashValue = await readFile(hashPath, 'utf8');
                try {
                    const groupingPath = join(HASH_GROUPING, hashValue);

                    const groupingHandle = await openIO(groupingPath);
                    try {
                        const pathURI = encodeURIComponent(path);

                        const groupingList = (
                            await groupingHandle.read('utf8')
                        ).split('\n').filter(v => v !== pathURI && v);

                        if (groupingList.length) {
                            await groupingHandle.write(groupingList.join('\n'), 'utf8');
                        } else {
                            await Promise.allSettled([groupingPath, join(HASH_FILE, hashValue)].map(p => unlink(p)));
                        }
                    } catch (error) { console.error(error); }

                    await groupingHandle.close();
                } catch (err) {
                    console.error(err);
                }
                await unlink(hashPath);
            } catch (error) {
                return error;
            }
        })()
    ]);

    if (deletion) {
        if (hashDeletion || mainDeletion)
            throw mainDeletion || hashDeletion;
    } else if (hashDeletion && mainDeletion)
        throw mainDeletion;
};

export const writeBuffer = (path, buffer, projectName, makeHash) => new Promise((resolve, reject) => {
    path = strapPath(path);
    streamWritableSource(path, makeHash, projectName, (err, result) => {
        if (err) reject(err);
        else resolve(result);
    }).end(buffer);
});

export const readBuffer = (path, projectName) => new Promise((resolve, reject) => {
    path = strapPath(path);

    let buffer = [];
    streamReadableSource(path, projectName)
        .on('data', buf => {
            buffer.push(buf);
        })
        .on('error', reject)
        .on('end', () => {
            resolve(Buffer.concat(buffer));
        });
});

const readFileSection = async (path, start, end) => {
    path = strapPath(path);

    const length = end - start;
    const buffer = Buffer.alloc(length); // Create a buffer to hold the specific section

    const handle = await open(path, 'r');

    try {
        const { bytesRead } = await handle.read({
            buffer,
            length,
            offset: 0,
            position: start
        });
        handle.close();
        return buffer.subarray(0, bytesRead);
    } catch (error) {
        handle.close();
        throw error;
    }
};

const strapPath = path => `/${normalizeRoute(path)}`;

const openIO = async (path, strictReader) => {
    let callback;

    const thisPromise = new Promise(resolve => {
        callback = () => {
            resolve();
            if (thisPromise === Scoped.SequentialIO[path])
                delete Scoped.SequentialIO[path];
        };
    });

    const lastPromise = Scoped.SequentialIO[path];
    Scoped.SequentialIO[path] = thisPromise;

    if (lastPromise) await lastPromise;

    try {
        return {
            close: callback,
            read: async (encoding) => {
                try {
                    const r = await readFile(path, encoding);
                    return r;
                } catch (error) {
                    if (strictReader) throw error;
                    return '';
                }
            },
            write: (data, encoding) => writeFile(path, data, encoding),
            append: (data, encoding) => appendFile(path, data, encoding)
        };
    } catch (error) {
        callback();
        throw error;
    }
};

const fileExists = async (path) => {
    path = strapPath(path);
    try {
        await access(path, constants.F_OK);
        return path;
    } catch (_) {
        return false;
    }
};

export const cleanupPendingHashes = async (projectName) => {
    const { PENDING_HASH_LOG, HASH_FILE } = STORAGE_DIRS(projectName);
    try {
        let residueError;
        const handler = await openIO(PENDING_HASH_LOG, true);
        try {
            await Promise.all(
                (await handler.read('utf8')).split('\n').map(async v => {
                    if (v) {
                        try {
                            await unlink(join(HASH_FILE, v));
                        } catch (_) { }
                    }
                })
            );
            await handler.write('', 'utf8');
        } catch (error) {
            residueError = { error };
        }
        await handler.close();
        if (residueError) throw residueError.error;
    } catch (error) {
        // console.error('cleanupPendingHashes err:', error);
    }
};