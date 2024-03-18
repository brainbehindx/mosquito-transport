import { ADMIN_DB_NAME, ADMIN_DB_URL, DEFAULT_DB } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js";

export const getDB = (projectName, name, url = DEFAULT_DB) => {
    if (!projectName) throw 'expected projectName in getDb()';
    if (url === 'admin' || url === 'default') throw `invalid database url: "${url}"`;

    const dbUrl = url === ADMIN_DB_URL ? 'admin' : url === DEFAULT_DB ? 'default' : url,
        { defaultName: dbName, instance } = Scoped.InstancesData[projectName].mongoInstances[dbUrl] || {};

    if (name === ADMIN_DB_NAME) name = dbName;
    if (!instance) throw `no MongoClient was found for database with url "${dbUrl}"`;
    if (!name && !dbName) throw `no dbName found for database with url "${dbUrl}"`;

    return instance.db(name || dbName);
};