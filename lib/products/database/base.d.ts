import { Db } from 'mongodb';

export function getDB(dbName?: string, dbUrl?: string): Db;