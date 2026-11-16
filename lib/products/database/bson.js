import { Buffer } from "buffer";
import { serialize } from "mongodb/lib/bson.js";

export const serializeToBase64 = doc =>
    Buffer.from(serialize(doc)).toString('base64');