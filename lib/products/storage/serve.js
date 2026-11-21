import { Scoped } from "../../helpers/variables.js";
import { ensureDir, getStringExtension, interpolate, normalizeRoute } from "../../helpers/utils.js";
import { validateJWT } from "../auth/tokenizer.js";
import { NO_CACHE_HEADER, STORAGE_DIRS, STORAGE_ROUTE, one_hour } from "../../helpers/values.js";
import { unlink } from "fs/promises";
import { exec } from "child_process";
import { createRequire } from 'node:module';
import { simplifyCaughtError, simplifyError } from 'simplify-error';
import { Validator } from "guard-object";
import { getSource } from "./store.js";
import { join } from "path";
import { throwRateLimit, useDDOS } from "../../helpers/ddos.js";
import mime from 'mime';
import LimitTasks from "limit-task";
import { cpus } from "os";

const _require = createRequire(import.meta.url);

/**
 * 
 * @param {any} param0 
 * @returns {import("express").Handler}
 */
export default function serve({
    projectName,
    logger,
    staticContentCacheControl,
    staticContentMaxAge,
    staticContentProps,
    transformMediaRoute: mediaRoute,
    transformMediaCleanupTimeout,
    ddosMap,
    maxFfmpegTasks,
    ffmpegEncoderArg,
    ipNode
}) {
    const hasLogger = logger.includes('all') || logger.includes('served-content');
    const hasErrorLogger = logger.includes('all') || logger.includes('error');

    return async (req, res, next) => {
        const route = `/${normalizeRoute(req.url)}`;

        if (typeof route === 'string' && route.startsWith(`${STORAGE_ROUTE}/`) && route.length > (STORAGE_ROUTE.length + 1)) {
            const now = hasLogger && performance.now();

            if (hasLogger) console.log('started route: ', route);

            try {
                useDDOS({
                    config: ddosMap,
                    requestPath: route,
                    route: 'storage',
                    ipNode,
                    req
                });
            } catch (error) {
                res.sendStatus(429);
                return;
            }

            const { 'mtoken': authToken } = req.headers;
            const auth =
                authToken &&
                await validateJWT(authToken, projectName)
                    .catch(() => null);
            const cleanRoute = route.substring(`${STORAGE_ROUTE}/`.length);
            const routeExtension = getStringExtension(cleanRoute);

            const { VID_CACHER } = STORAGE_DIRS(projectName);

            const rulesObj = {
                headers: { ...req.headers },
                ...auth ? { auth } : {},
                endpoint: 'serveFile',
                prescription: {
                    path: cleanRoute
                }
            };

            try {
                await Scoped.InstancesData[projectName].storageRules?.(rulesObj, throwRateLimit('storage'));
            } catch (e) {
                res.status(403).send({
                    status: 'error',
                    ...simplifyError('security_error', `${e}`)
                });
                return;
            }

            const routeTransformer =
                mediaRoute === '*' ||
                (mediaRoute || []).find(({ route }) =>
                    (route instanceof RegExp ? route.test(cleanRoute) : cleanRoute.startsWith(route))
                );
            const { searchParams } = new URL(req.url, `http://${req.headers.host}`);
            const pattern = {};

            [
                [['w', 'width'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
                [['h', 'height'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
                [['gray', 'grayscale'], (v) => v === '1' || v === 'true' || undefined],
                [['b', 'blur'], (v) =>
                    v === 'true' || (Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined)
                ],
                [['f', 'fit'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
                [['t', 'top'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
                [['l', 'left'], (v) => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
                [['mute'], (v) => v === '1' || v === 'true' || undefined],
                [['flip'], (v) => v === '1' || v === 'true' || undefined],
                [['flop'], (v) => v === '1' || v === 'true' || undefined],
                [['o', 'format'], (v) => v],
                [['q', 'quality'], (v) => {
                    const x = v * 1;
                    return (!Validator.NUMBER(x) || x > 1 || x < 0) ? undefined : x * 100;
                }],
                [['loss', 'lossless'], (v) => v === '1' || v === 'true' || undefined],
                [['vbr'], v => v],
                [['abr'], v => v],
                [['fps'], v => Validator.POSITIVE_NUMBER(v * 1) ? v * 1 : undefined],
                [['preset'], v => v]
            ].forEach(([paths, ext]) => {
                const v = paths.map(v => ext(searchParams.get(v) || undefined)).filter(v =>
                    v !== undefined
                )[0];

                if (v !== undefined) pattern[paths.slice(-1)[0]] = v;
            });

            const storagePath = normalizeRoute(req.path).substring(STORAGE_ROUTE.length);
            const { source } = await getSource(storagePath, projectName);

            if (routeTransformer) {
                const mediaType = getMediaType(routeExtension);
                let rib;

                try {
                    if (source) {
                        if (routeTransformer?.transform) {
                            rib = await routeTransformer.transform({ request: req, uri: source });
                            if (res.headersSent) return;
                        } else if (
                            (mediaType === 'image' || mediaType === 'video' || routeTransformer?.transformAs) &&
                            Object.keys(pattern).length
                        ) {
                            const { width, height, grayscale, blur, fit, top, left, flip, flop, format, quality, lossless, mute, vbr, abr, preset, fps } = pattern;

                            if (mediaType === 'image' || routeTransformer?.transformAs === 'image') {
                                const SharpLib = _require('sharp');
                                /**
                                 * @type {import("sharp").Sharp}
                                 */
                                let sharpInstance = SharpLib(source);

                                sharpInstance = sharpInstance.rotate();
                                if (top || left) {
                                    sharpInstance = sharpInstance.extract({ width, height, top, left });
                                } else if (fit || width || height)
                                    sharpInstance = sharpInstance.resize({ fit, height, width });

                                if (grayscale) sharpInstance = sharpInstance.grayscale(grayscale);
                                if (blur) sharpInstance = sharpInstance.blur(blur);
                                if (flip) sharpInstance = sharpInstance.flip(flip);
                                if (flop) sharpInstance = sharpInstance.flop(flop);
                                if (format || quality || lossless) {
                                    sharpInstance = sharpInstance.toFormat(format || (await sharpInstance.metadata()).format, {
                                        lossless, quality
                                    });
                                }

                                rib = await sharpInstance.toBuffer();
                            } else {
                                const com = [];
                                const crf = (quality || lossless) ? ' -crf ' + (quality ? interpolate(quality, [51, 0], [0, 100]) : 999) : '';
                                const sortedPattern = Object.entries(pattern)
                                    .sort((a, b) => (a > b) ? 1 : (a < b) ? -1 : 0)
                                    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join(',');

                                const outPath = join(VID_CACHER, `${encodeURIComponent(storagePath)}${sortedPattern}.${routeExtension || 'mp4'}`);

                                if (flip) com.push('vflip');
                                if (flop) com.push('hflip');
                                if (top || left) {
                                    com.push(`crop=${width}:${height}:${top}:${left}`);
                                } else if (width || height)
                                    com.push(`scale=${width || -1}:${height || -1}`);
                                if (grayscale) com.push(`colorchannelmixer=0.299:0.587:0.114`);

                                if (Scoped.cacheTranformVideoTimer[outPath]?.timer) {
                                    Scoped.cacheTranformVideoTimer[outPath].timer.refresh();
                                    rib = outPath;
                                } else {
                                    rib = await new Promise(async (resolve, reject) => {
                                        if (Scoped.cacheTranformVideoTimer[outPath]?.processing) {
                                            Scoped.cacheTranformVideoTimer[outPath].processList.push([resolve, reject]);
                                            return;
                                        }
                                        Scoped.cacheTranformVideoTimer[outPath] = {
                                            processing: true,
                                            inputFile: join(VID_CACHER, storagePath),
                                            processList: [[resolve, reject]]
                                        };
                                        const taskNode = `${projectName}${maxFfmpegTasks}`;

                                        const QueueTask = Validator.POSITIVE_INTEGER(maxFfmpegTasks) &&
                                            (
                                                Scoped.FfmpegTranscodeTask[taskNode] ||
                                                (Scoped.FfmpegTranscodeTask[taskNode] = LimitTasks(maxFfmpegTasks))
                                            );

                                        const GRAPHICS_LIB = ffmpegEncoderArg ? ` -c:v ${ffmpegEncoderArg?.trim?.()}` : ` -c:v libx264 -threads ${cpus().length}`;

                                        const ffmpegCommad = `ffmpeg -i "${source}"${mute ? ' -an' : ''}${com.length ? ' -vf "' + com.join(', ') + '"' : ''}${GRAPHICS_LIB}${mute ? '' : ' -c:a copy'}${crf}${vbr ? ' -b:v ' + vbr : ''}${abr ? ' -b:a' + abr : ''}${fps ? ' -r ' + fps : ''} -preset ${preset || 'medium'} "${await ensureDir(outPath)}"`;

                                        const transcodeVideo = () =>
                                            new Promise(resolve => {
                                                exec(ffmpegCommad, (err) => {
                                                    resolve();
                                                    if (!Scoped.cacheTranformVideoTimer[outPath]) return;
                                                    if (err) {
                                                        Scoped.cacheTranformVideoTimer[outPath].processList?.map?.(([_, deny]) => deny(err));
                                                        delete Scoped.cacheTranformVideoTimer[outPath];
                                                        unlink(outPath);
                                                    } else {
                                                        Scoped.cacheTranformVideoTimer[outPath].timer = setTimeout(() => {
                                                            clearTimeout(Scoped.cacheTranformVideoTimer[outPath].timer);
                                                            delete Scoped.cacheTranformVideoTimer[outPath];
                                                            unlink(outPath);
                                                        }, transformMediaCleanupTimeout || (one_hour * 7));
                                                        Scoped.cacheTranformVideoTimer[outPath].processList.map(([done]) => done(outPath));
                                                        delete Scoped.cacheTranformVideoTimer[outPath].processing;

                                                        if (Scoped.cacheTranformVideoTimer[outPath].processList)
                                                            delete Scoped.cacheTranformVideoTimer[outPath].processList;
                                                    }
                                                });
                                            });

                                        if (QueueTask) {
                                            QueueTask(transcodeVideo);
                                        } else transcodeVideo();
                                    });
                                }
                            }
                        } else rib = null;
                    }
                } catch (e) {
                    res.status(500).send(simplifyCaughtError(e).simpleError);
                    if (e && hasErrorLogger) console.log(`${route} err: ${e}`);
                    if (hasLogger) console.log(`${route} took: ${performance.now() - now}ms`);
                    return;
                }

                if (typeof rib === 'string') {
                    sendFile(rib);
                    return;
                } else if (Buffer.isBuffer(rib)) {
                    res.status(200).end(rib);
                    if (hasLogger) console.log(`${route} took: ${performance.now() - now}ms`);
                    return;
                } else if (rib !== null) {
                    res.set(NO_CACHE_HEADER);
                    res.sendStatus(404);
                    if (hasLogger) console.log(`${route} took: ${performance.now() - now}ms`);
                    return;
                }
            }

            function sendFile(path) {
                const type = mime.getType(req.path);
                if (type) res.set({ 'Content-Type': type });

                res.sendFile(path, {
                    ...staticContentProps,
                    ...staticContentMaxAge === undefined ? {} : { maxAge: staticContentMaxAge },
                    ...staticContentCacheControl === undefined ? {} : { cacheControl: staticContentCacheControl }
                }, (err) => {
                    if (err && hasErrorLogger) console.log(`${route} err: ${err}`);
                    if (hasLogger) console.log(`${route} took: ${performance.now() - now}ms`);
                });
            }
            if (source) {
                sendFile(source);
            } else {
                res.set(NO_CACHE_HEADER);
                res.sendStatus(404);
                if (hasLogger) console.log(`${route} took: ${performance.now() - now}ms`);
            }
        } else next();
    }
}

const getMediaType = (fileExtension) => {
    const imageExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'];
    const videoExtensions = ['mp4', 'mov', 'avi', 'mkv', 'wmv', 'flv'];

    const lowerCaseExtension = (fileExtension || '').toLowerCase();

    if (imageExtensions.includes(lowerCaseExtension)) {
        return 'image';
    } else if (videoExtensions.includes(lowerCaseExtension)) {
        return 'video';
    } else {
        return 'unknown';
    }
}