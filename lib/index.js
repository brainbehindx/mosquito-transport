import express from "express";
import compression from "compression";
import { databaseLiveRoutes, databaseRoutes, emitDatabase } from "./products/database/index.js";
import { authLiveRoutes, authRoutes } from "./products/auth/index.js";
import { storageRoutes } from "./products/storage/index.js";
import { Scoped } from "./helpers/variables.js";
import { IS_RAW_OBJECT, niceTry, simplifyError } from "./helpers/utils.js";
import { getDB } from "./products/database/base.js";
import { validateJWT } from "./products/auth/tokenizer.js";
import { ADMIN_DB_NAME, ADMIN_DB_URL, STORAGE_PATH, STORAGE_ROUTE } from "./helpers/values.js";
import { validateGoogleAuthConfig } from "./products/auth/googleAuth.js";
import { validateAppleAuthConfig } from "./products/auth/appleAuth.js";
import { validateFacebookAuthConfig } from "./products/auth/facebookAuth.js";
import { validateGithubAuthConfig } from "./products/auth/githubAuth.js";
import { validateTwitterAuthConfig } from "./products/auth/twitterAuth.js";
import { validateFallbackAuthConfig } from "./products/auth/fallbackAuth.js";
import { StorageListener } from "./helpers/listeners.js";
import GlobalListener from "./helpers/GlobalListener.js";
import EnginePath from "./helpers/EnginePath.js";
import { Server } from "socket.io";
import http from 'http';

const PORT = process.env.PORT || 4291;

const authorizeRequest = (accessKey) => (req, res, next) => {
    const incomingAccessKey = atob(req.headers.authorization?.split('Bearer ')?.join('') || ''),
        authToken = req.headers['mosquitodb-token'];

    if (authToken) req.headers.mtoken = authToken;

    if (incomingAccessKey !== accessKey) {
        res.status(403).send({ status: 'error', ...simplifyError('incorrect_access_key', 'The accessKey been provided is not correct') });
    } else next();
}

const serveStorage = ({ projectName }) => async (req, res, next) => {
    const route = req.url;

    console.log('route: ', route);

    if (typeof route === 'string' && route.startsWith(`${STORAGE_ROUTE}/`)) {
        const { 'mosquitodb-token': authToken } = req.headers,
            auth = authToken ? await niceTry(() => validateJWT(authToken, projectName)) : null,
            cleanRoute = route.substring(`${STORAGE_ROUTE}/`.length);

        const rulesObj = {
            ...(auth ? { auth: { ...auth, token: authToken } } : {}),
            operation: 'serverFile',
            route: cleanRoute
        };

        try {
            await Scoped.StorageRules[projectName]?.(rulesObj);
        } catch (e) {
            res.status(403).send({ status: 'error', ...simplifyError('security_error', `${e}`) });
            return;
        }

        res.sendFile(`${STORAGE_PATH(projectName)}/${cleanRoute}`, {}, (err) => {
            // console.log('serveStorage: ', err);
            // if (err) {
            //     // res.status(404).send({ status: 'error', ...simplifyError('unexpected_error', `${err}`) });
            // } else
            //  res.status().end();
        });
    } else next();
}

const useMosquitoDbServer = (app, config) => {
    const { projectName, port, accessKey, logger } = config;

    app.disable("x-powered-by");
    if (!logger)
        app.use((req, res, next) => {
            console.log('started route:', req.url);
            next();
        });

    [
        compression(),
        serveStorage({ projectName }),
        // app.use(STORAGE_ROUTE, express.static(STORAGE_PATH(projectName, ''))),
        express.urlencoded({ type: 'multipart/*', limit: 96751471, extended: false }),
        express.json({ type: '*/json', limit: '20gb' }),
        authorizeRequest(accessKey),
        ...authRoutes({ ...config }),
        ...databaseRoutes({ projectName }),
        ...storageRoutes({ projectName })
    ].forEach(e => {
        app.use(e);
    });

    if (!logger)
        app.use((req, _, next) => {
            console.log('finished route:', req.url);
            next();
        });

    const server = http.createServer(app),
        io = new Server(server);

    io.on('connection', socket => {
        authLiveRoutes({ projectName }).map(e => e(socket));
        databaseLiveRoutes({ projectName }).map(e => e(socket));
    });

    server.listen(port, () => {
        console.log(`mosquitodb server listening on port ${PORT}`);
    });
}


export default class MosquitoDbServer {
    constructor(config) {
        validateServerConfig(config);
        const {
            signerKey,
            storageRules,
            databaseRules,
            port,
            enableSequentialUid,
            disableCrossLogin,
            accessKey,
            logger,
            dbUrl
        } = config;

        this.projectName = config.projectName.trim();
        this.port = port || PORT;

        if (Scoped.serverInstances[this.projectName])
            throw `Cannot initialize MosquitoDbServer() with projectName:"${this.projectName}" multiple times`;

        if (Scoped.expressInstances[`${this.port}`])
            throw `Port ${this.port} is currently being used by another MosquitoDbServer() instance`;

        Scoped.expressInstances[`${this.port}`] = express();
        Scoped.DatabaseUrl[this.projectName] = dbUrl;

        useMosquitoDbServer(Scoped.expressInstances[`${this.port}`], {
            ...config,
            projectName: this.projectName,
            port: this.port,
            accessKey,
            logger
        });

        StorageListener[this.projectName] = new GlobalListener();

        Scoped.DatabaseRules[this.projectName] = databaseRules;
        Scoped.StorageRules[this.projectName] = storageRules;
        Scoped.AuthHashToken[this.projectName] = signerKey;
        Scoped.SequentialUid[this.projectName] = 0; // TODO: resume value
        Scoped.EnableSequentialUid[this.projectName] = !!enableSequentialUid;
        Scoped.DisableCrossLogin[this.projectName] = !!disableCrossLogin;
    }

    getDatabase = (dbName, dbUrl) => {
        if (dbName === ADMIN_DB_NAME) throw `getDatabase() first argument cannot be ${ADMIN_DB_NAME}`;
        return getDB(this.projectName, dbName, dbUrl);
    };

    listenHttpsRequest(route = '', callback, options) {
        Scoped.expressInstances[`${this.port}`].use(express.Router({ caseSensitive: true }).all(`${this.projectName}${route.startsWith('/') ? '' : '/'}${route}`, async (req, res) => {
            const { 'mosquitodb-token': authToken } = req.headers;
            let auth;

            try {
                if (authToken && (options?.enforceUser || options?.validateUser)) {
                    auth = await validateJWT(authToken, this.projectName);
                } else if (options?.enforceUser) throw simplifyError('unauthorize_access', 'Only authorized users can access this request');
            } catch (e) {
                if (options?.enforceUser) {
                    res.status(403).send({ status: 'error', ...e });
                    return;
                }
            }

            callback(req, res, auth ? { ...auth, token: authToken } : null);
        }));
    }

    listenDatabase(path, callback, options) {
        if (options?.dbName === ADMIN_DB_NAME) throw `listenDatabase() dbName can have any string value but not '${ADMIN_DB_NAME}'`;
        if (options?.dbUrl === ADMIN_DB_NAME) throw `listenDatabase() dbUrl can have any string value but not '${ADMIN_DB_URL}'`;

        return emitDatabase(path, callback, options);
    }

    listenStorage(path, callback) {
        if (typeof path !== 'string') throw `path is invalid in listenStorage(), expected a string value but got ${typeof path}`;
        return StorageListener[this.projectName].startKeyListener(path, callback);
    }

    listenNewUser = (callback) => emitDatabase(EnginePath.userAcct(), s => {
        if (s.insertion) callback?.({ ...s.insertion });
    });

    updateUserProfile(profile) {

    }

    extractBackup() { }
    updateUserClaims() { }
    updateUserEmailAddress() { }
    updateUserPassword() { }
    listenDeletedUser() { }

    // listenClaimsChange() { }
}

const projectNameWrongChar = ['/', '\\', '.', '$', '%', '#', '!', '*', '?'];
const loggerOptions = ['all', 'disabled', 'auth', 'database', 'storage', 'outside-requests', 'content']

const validateServerConfig = (config) => {
    if (!IS_RAW_OBJECT(config))
        throw 'Expected a raw object in MosquitoDbServer() constructor';

    const {
        projectName,
        signerKey,
        storageRules,
        databaseRules,
        port,
        enableSequentialUid,
        accessKey,
        disableCrossLogin,
        logger,
        dbUrl,
        mergeAuthAccount,
        googleAuthConfig,
        appleAuthConfig,
        facebookAuthConfig,
        githubAuthConfig,
        twitterAuthConfig,
        fallbackAuthConfig
    } = config;

    if (!projectName?.trim() || typeof projectName.trim() !== 'string')
        throw '"projectName" is required in MosquitoDbServer() constructor';

    if (!accessKey?.trim() || typeof accessKey.trim() !== 'string')
        throw '"accessKey" is required in MosquitoDbServer() constructor';

    if (projectNameWrongChar.filter(v => projectName.includes(v)).length)
        throw `projectName must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (projectNameWrongChar.filter(v => `${port || ''}`.includes(v)).length)
        throw `port must not contain any of this characters: ${projectNameWrongChar.join(', ')}`;

    if (databaseRules && typeof databaseRules !== 'function')
        throw `databaseRules type must be function but got ${typeof databaseRules}`;

    if (storageRules && typeof storageRules !== 'function')
        throw `storageRules type must be function but got ${typeof storageRules}`;

    if ((signerKey?.trim() || '').length !== 90 || typeof signerKey?.trim() !== 'string')
        throw `signerKey must have string length equals to 90 trimmed characters`;

    if (enableSequentialUid !== undefined && typeof enableSequentialUid !== 'boolean')
        throw `invalid value supplied to enableSequentialUid, expected a boolean but got ${typeof enableSequentialUid}`;

    if (disableCrossLogin !== undefined && typeof disableCrossLogin !== 'boolean')
        throw `invalid value supplied to disableCrossLogin, expected a boolean but got ${typeof disableCrossLogin}`;

    if (mergeAuthAccount !== undefined && typeof mergeAuthAccount !== 'boolean')
        throw `invalid value supplied to mergeAuthAccount, expected a boolean but got ${typeof disableCrossLogin}`;

    if (logger && (Array.isArray(logger) ? logger : [logger]).filter(v => !loggerOptions.includes(v)).length)
        throw `invalid value supplied to logger, expected any of ${loggerOptions.join(', ')}`;

    if (dbUrl && typeof dbUrl !== 'string') throw `dbUrl must be a string`;

    if (googleAuthConfig) validateGoogleAuthConfig(googleAuthConfig);
    if (appleAuthConfig) validateAppleAuthConfig(googleAuthConfig);
    if (facebookAuthConfig) validateFacebookAuthConfig(googleAuthConfig);
    if (githubAuthConfig) validateGithubAuthConfig(googleAuthConfig);
    if (twitterAuthConfig) validateTwitterAuthConfig(googleAuthConfig);
    if (fallbackAuthConfig) validateFallbackAuthConfig(googleAuthConfig);
}

const server = new MosquitoDbServer({
    projectName: 'inspire',
    signerKey: 'sftgersgrdhbdfshbdfhdfshertryhegrweermasfifqweifewfjewfewekwkdkwwrqr3t4tfoaworwqriwqirwrwq',
    accessKey: 'dfjifskskksos',
    googleAuthConfig: {
        clientID: '1073395965256-a1evsulddv8mf3hmtptj2jkncdqqfvqu.apps.googleusercontent.com' || '1073395965256-khp45jgfo6tp8ua7nvoc0l6lqoj1q878.apps.googleusercontent.com'
    }
});

// server.listenDatabase();


// {
//     _id: {
//       _data: '82646741EF000000012B022C0100296E5A1004C80A5C641AB34163813A9962304A8CDB463C5F6964003C363436373431626438333563386336393539643236663139000004'
//     },
//     operationType: 'insert',
//     clusterTime: new Timestamp({ t: 1684488687, i: 1 }),
//     wallTime: 2023-05-19T09:31:27.640Z,
//     fullDocument: { _id: '646741bd835c8c6959d26f19', user: 'Ademola Onabanjo' },
//     ns: { db: 'ADMIN_DB:inspire', coll: 'testNode' },
//     documentKey: { _id: '646741bd835c8c6959d26f19' }
// }

// {
//     _id: {
//       _data: '82646742AC000000022B022C0100296E5A1004C80A5C641AB34163813A9962304A8CDB463C5F6964003C363436373431626438333563386336393539643236663139000004'
//     },
//     operationType: 'update',
//     clusterTime: new Timestamp({ t: 1684488876, i: 2 }),
//     wallTime: 2023-05-19T09:34:36.157Z,
//     ns: { db: 'ADMIN_DB:inspire', coll: 'testNode' },
//     documentKey: { _id: '646741bd835c8c6959d26f19' },
//     updateDescription: {
//       updatedFields: { user: 'Anthony Onabanjo' },
//       removedFields: [],
//       truncatedArrays: []
//     }
// }

// {
//     _id: {
//       _data: '826467436A000000022B022C0100296E5A1004C80A5C641AB34163813A9962304A8CDB463C5F6964003C363436373431626438333563386336393539643236663139000004'
//     },
//     operationType: 'update',
//     clusterTime: new Timestamp({ t: 1684489066, i: 2 }),
//     wallTime: 2023-05-19T09:37:46.954Z,
//     ns: { db: 'ADMIN_DB:inspire', coll: 'testNode' },
//     documentKey: { _id: '646741bd835c8c6959d26f19' },
//     updateDescription: {
//       updatedFields: { food: 'rice and beans' },
//       removedFields: [ 'user' ],
//       truncatedArrays: []
//     }
// }

// {
//     _id: {
//       _data: '8264675546000000012B022C0100296E5A1004C80A5C641AB34163813A9962304A8CDB463C5F6964003C363436373534646138333563386336393539643236663162000004'
//     },
//     operationType: 'insert',
//     clusterTime: new Timestamp({ t: 1684493638, i: 1 }),
//     wallTime: 2023-05-19T10:53:58.458Z,
//     fullDocument: {
//       _id: '646754da835c8c6959d26f1b',
//       type: 'This is the second update',
//       user: 'Ifeoluwa Onabanjo'
//     },
//     ns: { db: 'ADMIN_DB:inspire', coll: 'testNode' },
//     documentKey: { _id: '646754da835c8c6959d26f1b' }
// }

// {
//     _id: {
//       _data: '82646755AE000000012B022C0100296E5A1004C80A5C641AB34163813A9962304A8CDB463C5F6964003C363436373534646138333563386336393539643236663162000004'
//     },
//     operationType: 'delete',
//     clusterTime: new Timestamp({ t: 1684493742, i: 1 }),
//     wallTime: 2023-05-19T10:55:42.069Z,
//     ns: { db: 'ADMIN_DB:inspire', coll: 'testNode' },
//     documentKey: { _id: '646754da835c8c6959d26f1b' }
// }