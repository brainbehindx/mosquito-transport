import { Db } from 'mongodb';

export function getDB(projectName?: string, dbName?: string, dbUrl?: string): Db;