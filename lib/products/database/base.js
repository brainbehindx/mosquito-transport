import { MongoClient } from "mongodb";
import { DEFAULT_DB_NAME, DEFAULT_DB_URL } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js";

export const getDB = (projectName, name, url) => {
    if (!projectName) throw 'expected projectName in getDb()';

    const dbName = `${name || Scoped.DatabaseName[projectName] || DEFAULT_DB_NAME}:${projectName}`,
        dbUrl = `${url || Scoped.DatabaseUrl[projectName] || DEFAULT_DB_URL}`;

    if (!Scoped.Databases[dbUrl]) {
        Scoped.Databases[dbUrl] = { client: new MongoClient(dbUrl), db: {} };
        Scoped.Databases[dbUrl].client.connect().then(() => {
            console.log(`connected to mongodb at ${dbUrl}`);
        }).catch(e => {
            console.error(`failed to connected to mongodb at ${dbUrl}: ${e}`)
        });
    }
    if (!Scoped.Databases[dbUrl].db[dbName])
        Scoped.Databases[dbUrl].db[dbName] = Scoped.Databases[dbUrl].client.db(dbName);

    return Scoped.Databases[dbUrl].db[dbName];
};