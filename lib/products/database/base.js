import { ADMIN_DB_NAME, ADMIN_DB_URL, DEFAULT_DB } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js";

/**
 * @type {(projectName: string, dbName?: string, dbUrl?: string) => import('mongodb').Db}
 */
export const getDB = (projectName, name, url = DEFAULT_DB) => {
    if (!projectName) throw 'expected projectName in getDb()';
    const { dbName, instance } = getDbNaming(projectName, name, url) || {};
    return instance.instance.db(dbName);
};

export const getDbNaming = (projectName, name, dbRef = DEFAULT_DB) => {
    if (!projectName) throw 'expected projectName in getDb()';
    if (dbRef === 'admin' || dbRef === 'default') throw `reserved keyword dbRef: "${dbRef}"`;

    dbRef = dbRef === ADMIN_DB_URL ? 'admin' : dbRef === DEFAULT_DB ? 'default' : dbRef;
    const instance = Scoped.InstancesData[projectName].mongoInstances[dbRef];

    if (!instance) throw `no MongoClient was found for database with dbRef "${dbRef}"`;

    return {
        dbRef,
        instance,
        dbName: name === ADMIN_DB_NAME ? instance.defaultName : (name || instance.defaultName)
    };
}