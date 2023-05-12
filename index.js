import express from "express";
import compression from "compression";
import { databaseRoutes } from "./lib/products/database/index.js";
import bodyParser from 'body-parser';
import { authRoutes } from "./lib/products/auth/index.js";
import { storageRoutes } from "./lib/products/storage/index.js";
import { Scoped } from "./lib/helpers/variables.js";
import { IS_RAW_OBJECT } from "./lib/helpers/utils.js";
import { getDB } from "./lib/products/database/base.js";

const PORT = process.env.PORT || 4291;

const useMosquitoDbServer = (app, projectName, port) => {
    app.disable("x-powered-by");

    [
        compression(),
        bodyParser.json(),
        ...authRoutes(projectName),
        ...databaseRoutes(projectName),
        ...storageRoutes(projectName)
    ].forEach(e => {
        app.use(e);
    });

    app.listen(port, () => {
        console.log(`mosquitodb server listening on port ${PORT}`);
    });
}

export default class MosquitoDbServer {
    constructor(config) {
        validateServerConfig(config);
        const { signerKey, storageRules, databaseRules, port, enableSequentialUid, disableCrossLogin } = config;

        this.projectName = config.projectName.trim();
        this.port = port || PORT;

        if (Scoped.serverInstances[this.projectName])
            throw `Cannot initialize MosquitoDbServer() with projectName:"${this.projectName}" multiple times`;

        if (Scoped.expressInstances[`${this.port}`])
            throw `Port ${this.port} is currently being used by another MosquitoDbServer() instance`;

        Scoped.expressInstances[`${this.port}`] = express();

        useMosquitoDbServer(Scoped.expressInstances[`${this.port}`], this.projectName, this.port);

        Scoped.DatabaseRules[this.projectName] = databaseRules;
        Scoped.StorageRules[this.projectName] = storageRules;
        Scoped.AuthHashToken[this.projectName] = signerKey;
        Scoped.SequentialUid[this.projectName] = 0; // resume value
        Scoped.EnableSequentialUid[this.projectName] = !!enableSequentialUid;
        Scoped.DisableCrossLogin[this.projectName] = !!disableCrossLogin;
    }

    getDatabase = (dbName, dbUrl) => getDB(this.projectName, dbName, dbUrl);
    listenDatabase() { }
    listenStorage() { }
    listenHttpsRequest() { }
    retrieveBackup() { }
    listenNewUser() { }
    updateUserProfile() { }
    updateUserClaims() { }
    updateUserEmailAddress() { }
    updateUserPassword() { }
    listenDeletedUser() { }
    listenVerifyState() { }
    listenClaimsChange() { }
}

const projectNameWrongChar = ['/', '\\', '.', '$', '%', '#', '!', '*', '?'];

const validateServerConfig = (config) => {
    if (!IS_RAW_OBJECT(config))
        throw 'Expected a raw object in MosquitoDbServer() constructor';

    const { projectName, signerKey, storageRules, databaseRules, port, enableSequentialUid } = config;
    if (!projectName?.trim() || typeof projectName.trim() !== 'string')
        throw '"projectName" is required in MosquitoDbServer() constructor';

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
}