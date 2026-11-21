import { databaseLivePath, dbRoute } from "./products/database/index.js";
import { authLivePath, authRouteName } from "./products/auth/index.js";
import { storageRouteName } from "./products/storage/index.js";
import { one_hour, one_mb, one_minute } from "./helpers/values.js";
import { validateGoogleAuthConfig } from "./products/auth/google_auth.js";
import { validateAppleAuthConfig } from "./products/auth/apple_auth.js";
import { validateFacebookAuthConfig } from "./products/auth/facebook_auth.js";
import { validateGithubAuthConfig } from "./products/auth/github_auth.js";
import { validateTwitterAuthConfig } from "./products/auth/twitter_auth.js";
import { validateFallbackAuthConfig } from "./products/auth/custom_auth.js";
import { Db } from "mongodb";
import { Validator } from "guard-object";
import { validateDDOS_Config } from "./helpers/ddos.js";

export const validateServerConfig = (config, that) => {
    if (!Validator.OBJECT(config))
        throw `Expected a raw object in ${that.constructor.name}() constructor`;

    const {
        projectName,
        signerKey,
        storageRules,
        databaseRules,
        port,
        enableSequentialUid,
        logger,
        mongoInstances,
        mergeAuthAccount,
        interceptNewAuth,
        googleAuthConfig,
        appleAuthConfig,
        facebookAuthConfig,
        githubAuthConfig,
        twitterAuthConfig,
        fallbackAuthConfig,
        externalAddress,
        hostname,
        maxRequestBufferSize,
        maxUploadBufferSize,
        uidLength,
        accessTokenInterval,
        refreshTokenExpiry,
        dumpsterPath,
        transformMediaRoute,
        e2eKeyPair,
        enforceE2E,
        preMiddlewares,
        transformMediaCleanupTimeout,
        onUserMounted,
        ddosMap,
        ipNode,
        internals,
        onSocketSnapshot,
        onSocketError,
        useSocketServer,
        onHandleTokenUpgrade,
        autoPurgeToken,
        enableStatefulAccessToken,
        ffmpegEncoderArg,
        maxFfmpegTasks,
        pingTimeout,
        pingInterval
    } = config;

    if (
        transformMediaCleanupTimeout !== undefined &&
        (!Number.isInteger(transformMediaCleanupTimeout) || transformMediaCleanupTimeout <= 0)
    ) throw new Error(`"transformMediaCleanupTimeout" expected a positive integer value`);
    if (
        preMiddlewares !== undefined &&
        typeof preMiddlewares !== 'function' &&
        (!Array.isArray(preMiddlewares) || preMiddlewares.filter(v => typeof v !== 'function').length)
    ) throw new Error(`"preMiddlewares" must be an array of middleware functions`);

    if (typeof projectName !== 'string' || !projectName.trim())
        throw new Error(`"projectName" is required in ${that.constructor.name}() constructor`);

    if (projectName.trim() === 'storage')
        throw new Error(`"storage" is a reserver value for "projectName"`);

    let hasDefault, hasAdmin;
    Object.entries(mongoInstances)
        .forEach(([key, value]) => {
            if (!(value instanceof Db))
                throw new Error(`invalid value supplied to mongoInstance['${key}'], expected an instance of mongodb Db`);

            if (key === 'default') hasDefault = value.databaseName;
            if (key === 'admin') hasAdmin = value.databaseName;
        });

    if (!hasDefault) throw new Error(`A default mongoInstance must be provided`);
    if (!hasAdmin) throw new Error(`An admin mongoInstance must be provided`);

    if(hasDefault === hasAdmin)
        throw new Error(`admin mongoInstance must have a different name to the default instance`);

    if (dumpsterPath !== undefined && (typeof dumpsterPath !== 'string' || !dumpsterPath.trim() || dumpsterPath.endsWith('/')))
        throw new Error('"dumpsterPath" must be a local path string and not end with a "/"');

    if (e2eKeyPair !== undefined && (
        !Array.isArray(e2eKeyPair) ||
        e2eKeyPair.length !== 2 ||
        e2eKeyPair.filter(v => typeof v !== 'string').length
    )) throw new Error(`"e2eKeyPair" expected an array of 2 base64 string`);

    if (enforceE2E !== undefined) {
        if (typeof enforceE2E !== 'boolean') throw new Error(`"enforceE2E" must be a boolean`);
        if (enforceE2E && !e2eKeyPair) throw new Error(`enabling "enforceE2E" requires providing a "e2eKeyPair"`);
    }

    if (transformMediaRoute !== undefined) validateResizableMediaRoute(transformMediaRoute);

    if (projectNameWrongChar.filter(v => projectName.includes(v)).length)
        throw new Error(`projectName must not contain any of this characters: ${projectNameWrongChar.join(', ')}`);

    if (projectNameWrongChar.filter(v => `${port || ''}`.includes(v)).length)
        throw new Error(`port must not contain any of this characters: ${projectNameWrongChar.join(', ')}`);

    if (maxRequestBufferSize !== undefined && (!Validator.POSITIVE_INTEGER(maxRequestBufferSize) || maxRequestBufferSize < one_mb))
        throw new Error(`"maxRequestBufferSize" must be a positive integer not lesser than ${one_mb}(1mb)`);

    if (maxUploadBufferSize !== undefined && (!Validator.POSITIVE_INTEGER(maxUploadBufferSize) || maxUploadBufferSize < 1024))
        throw new Error(`"maxUploadBufferSize" must be a positive integer not lesser than 1024 (1kb)`);

    if (pingInterval !== undefined && (!Validator.POSITIVE_INTEGER(pingInterval) || pingInterval < 300))
        throw new Error(`"pingInterval" must be a positive integer not lesser than 300`);

    if (pingTimeout !== undefined && (!Validator.POSITIVE_INTEGER(pingTimeout) || pingTimeout < 300))
        throw new Error(`"pingTimeout" must be a positive integer not lesser than 300`);

    if (databaseRules !== undefined && typeof databaseRules !== 'function')
        throw new Error(`databaseRules type must be function but got ${typeof databaseRules}`);

    if (storageRules !== undefined && typeof storageRules !== 'function')
        throw new Error(`storageRules type must be function but got ${typeof storageRules}`);

    if (onSocketSnapshot !== undefined && typeof onSocketSnapshot !== 'function')
        throw new Error(`onSocketSnapshot type must be function but got ${typeof onSocketSnapshot}`);

    if (onSocketError !== undefined && typeof onSocketError !== 'function')
        throw new Error(`onSocketError type must be function but got ${typeof onSocketError}`);

    if (useSocketServer !== undefined && typeof useSocketServer !== 'function')
        throw new Error(`useSocketServer type must be function but got ${typeof useSocketServer}`);

    if (onHandleTokenUpgrade !== undefined && typeof onHandleTokenUpgrade !== 'function')
        throw new Error(`onHandleTokenUpgrade type must be function but got ${typeof onHandleTokenUpgrade}`);

    if (typeof signerKey !== 'string' || signerKey.length < 32)
        throw new Error(`signerKey must be at least 32 characters`);

    if (enableSequentialUid !== undefined && typeof enableSequentialUid !== 'boolean')
        throw new Error(`invalid value supplied to enableSequentialUid, expected a boolean but got ${typeof enableSequentialUid}`);

    if (autoPurgeToken !== undefined && typeof autoPurgeToken !== 'boolean')
        throw new Error(`invalid value supplied to autoPurgeToken, expected a boolean but got ${typeof autoPurgeToken}`);

    if (enableStatefulAccessToken !== undefined && typeof enableStatefulAccessToken !== 'boolean')
        throw new Error(`invalid value supplied to enableStatefulAccessToken, expected a boolean but got ${typeof enableStatefulAccessToken}`);

    if (mergeAuthAccount !== undefined && typeof mergeAuthAccount !== 'boolean')
        throw new Error(`invalid value supplied to mergeAuthAccount, expected a boolean but got ${typeof mergeAuthAccount}`);

    if (uidLength !== undefined && (!Validator.POSITIVE_INTEGER(uidLength) || uidLength < 10))
        throw new Error(`invalid value supplied to uidLength, expected a positive integer greater than 9`);

    if (refreshTokenExpiry !== undefined && (
        !Validator.POSITIVE_INTEGER(refreshTokenExpiry) ||
        refreshTokenExpiry < one_hour ||
        (Validator.POSITIVE_INTEGER(accessTokenInterval) && accessTokenInterval >= refreshTokenExpiry)
    )) {
        if (Validator.POSITIVE_INTEGER(accessTokenInterval) && accessTokenInterval >= refreshTokenExpiry)
            throw new Error('"refreshTokenExpiry" must be greater than "accessTokenInterval"');
        throw new Error(`invalid value supplied to accessTokenInterval, expected a positive integer greater/equals than ${one_hour}(1 hour)`);
    }

    if (accessTokenInterval !== undefined && (!Validator.POSITIVE_INTEGER(accessTokenInterval) || accessTokenInterval < one_minute * 10))
        throw new Error(`invalid value supplied to accessTokenInterval, expected a positive integer greater/equals than ${one_minute * 10}(10 minutes)`);

    if (logger && (Array.isArray(logger) ? logger : [logger]).some(v => !loggerOptions.includes(v)))
        throw new Error(`invalid value supplied to logger, expected any of ${loggerOptions.join(', ')}`);
    if (externalAddress !== undefined && typeof externalAddress !== 'string')
        throw new Error(`externalAddress must be a string`);
    if (hostname !== undefined && typeof hostname !== 'string')
        throw new Error(`hostname must be a string`);

    if (interceptNewAuth !== undefined && typeof interceptNewAuth !== 'function')
        throw new Error('"interceptNewAuth" must be a function');
    if (onUserMounted !== undefined && typeof onUserMounted !== 'function')
        throw new Error('"onUserMounted" must be a function');
    if (ddosMap !== undefined) validateDDOS_Config(ddosMap);
    if (ipNode !== undefined) {
        if ((typeof ipNode !== 'string' || !ipNode.trim()) && typeof ipNode !== 'function')
            throw new Error(`expected either a non-empty string or a function at "ipNode" but got ${ipNode}`);
    }
    if (internals) {
        const features = ['database', 'auth', 'storage'];
        if (!Validator.OBJECT(internals)) throw new Error(`internals must be an object but got ${internals}`);
        Object.entries(internals).forEach(([k, v]) => {
            if (!features.includes(k)) throw new Error(`unknown property "${k}", expected any of ${k}`);
            const values = Object.values(InternalRoutes[k]);

            if (
                typeof v !== 'boolean' &&
                (!Array.isArray(v) || v.some(s => !values.includes(s)))
            ) {
                throw new Error(`expected a boolean value or an array with any of "${values}" at internals.${k} but got ${v}`);
            }
        });
    }
    if (ffmpegEncoderArg !== undefined && typeof ffmpegEncoderArg !== 'string')
        throw new Error(`ffmpegEncoderArg must be a string but got ${ffmpegEncoderArg}`);
    if (maxFfmpegTasks !== undefined && (!Validator.POSITIVE_INTEGER(maxFfmpegTasks) || maxFfmpegTasks < 1))
        throw new Error(`maxFfmpegTasks must be a positive integer greater than zero`);

    if (googleAuthConfig) validateGoogleAuthConfig(googleAuthConfig);
    if (appleAuthConfig) validateAppleAuthConfig(appleAuthConfig);
    if (facebookAuthConfig) validateFacebookAuthConfig(facebookAuthConfig);
    if (githubAuthConfig) validateGithubAuthConfig(githubAuthConfig);
    if (twitterAuthConfig) validateTwitterAuthConfig(twitterAuthConfig);
    if (fallbackAuthConfig) validateFallbackAuthConfig(fallbackAuthConfig);
};

const transformRoutes = t => Object.fromEntries(t.map(v => [v, v]));

export const InternalRoutes = {
    auth: transformRoutes([...authRouteName, ...authLivePath]),
    database: transformRoutes([...dbRoute, ...databaseLivePath]),
    storage: transformRoutes(storageRouteName)
};

const projectNameWrongChar = ['/', '\\', '.', '$', '%', '#', '!', '*', '?'];
const loggerOptions = ['all', 'auth', 'database', 'storage', 'external-requests', 'served-content', 'database-snapshot', 'error'];

const validateResizableMediaRoute = (v) => {
    if (v !== '*') {
        if (!Array.isArray(v)) throw new Error('"transformMediaRoute" expected either "*" or an array');
        v.forEach((v, i) => {
            if (!(v?.route instanceof RegExp) && typeof v?.route !== 'string')
                throw new Error(`"transformMediaRoute" array at index ${i} expected "route" to be either RegularExpression or string but got ${v?.route}`);
            if (v?.transform !== undefined && typeof v?.transform !== 'function')
                throw new Error(`"transformMediaRoute" array at index ${i} expected "transform" to be a function`);
            if (v?.transformAs !== undefined && v.transformAs !== 'image' && v.transformAs !== 'video')
                throw new Error(`"transformAs" must be either "image" or "video" but got "${v.transformAs}"`);
        });
    }
};