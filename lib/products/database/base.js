import { ADMIN_DB_NAME, ADMIN_DB_URL, DEFAULT_DB } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js";

/**
 * @type {(projectName: string, dbName?: string, dbUrl?: string) => import('mongodb').Db}
 */
export const getDB = (projectName, name, url = DEFAULT_DB) => {
    if (!projectName) throw 'expected projectName in getDb()';
    const { defaultName: dbName, instance } = getDbInstance(projectName, url) || {};

    if (name === ADMIN_DB_NAME) name = dbName;
    if (!instance) throw `no MongoClient was found for database with dbRef "${url}"`;
    // if (!name && !dbName) throw `no dbName found for database with dbRef "${dbUrl}"`;

    return instance.db(name || dbName);
};

export const getDbInstance = (projectName, dbUrl = DEFAULT_DB) => {
    if (!projectName) throw 'expected projectName in getDb()';
    if (dbUrl === 'admin' || dbUrl === 'default') throw `reserved keyword dbRef: "${dbUrl}"`;

    dbUrl = dbUrl === ADMIN_DB_URL ? 'admin' : dbUrl === DEFAULT_DB ? 'default' : dbUrl;
    return Scoped.InstancesData[projectName].mongoInstances[dbUrl];
}