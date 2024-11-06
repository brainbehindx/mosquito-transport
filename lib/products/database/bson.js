import { Buffer } from "buffer";
import { deserialize, serialize } from "mongodb/lib/bson";

export const deserializeBSON = (data, downcast) => {
    if (typeof data === 'string')
        data = Buffer.from(data, 'base64');

    return deserialize(data, {
        bsonRegExp: !downcast,
        promoteLongs: !!downcast,
        promoteValues: !!downcast,
        promoteBuffers: !!downcast
    });
};

export const serializeToBase64 = doc => Buffer.from(serialize(doc)).toString('base64');