import { ADMIN_DB_NAME, ADMIN_DB_URL, DEFAULT_DB } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js";

/**
 * @type {(projectName: string, dbName?: string, dbUrl?: string) => import('mongodb').Db}
 */
export const getDB = (projectName, name, url = DEFAULT_DB) => {
    if (!projectName) throw 'expected projectName in getDb()';
    if (url === 'admin' || url === 'default') throw `reserved keyword dbRef: "${url}"`;

    const dbUrl = url === ADMIN_DB_URL ? 'admin' : url === DEFAULT_DB ? 'default' : url;
    const { defaultName: dbName, instance } = getDbInstance(projectName, dbUrl) || {};

    if (name === ADMIN_DB_NAME) name = dbName;
    if (!instance) throw `no MongoClient was found for database with dbRef "${dbUrl}"`;
    // if (!name && !dbName) throw `no dbName found for database with dbRef "${dbUrl}"`;

    return instance.db(name || dbName);
};

export const getDbInstance = (projectName, dbUrl) => Scoped.InstancesData[projectName].mongoInstances[dbUrl];