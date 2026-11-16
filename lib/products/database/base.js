import { DEFAULT_DB } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js";

/**
 * @type {(projectName: string, url?: string, dbName?: string) => import('mongodb').Db}
 */
export const getDB = (projectName, key = DEFAULT_DB, name) => {
    if (!projectName) throw new Error('expected projectName in getDb()');

    const db = Scoped.InstancesData[projectName].mongoInstances[key];
    if (!db) throw new Error(`no Db instance was found for database with reference "${key}"`);

    if (name) return db.client.db(name);
    return db;
}