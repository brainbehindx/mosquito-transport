
export const simplifyError = (error, message) => ({
    simpleError: { error, message }
});

export const simplifyCaughtError = (e) => e?.simpleError ? e : simplifyError('unexpected_error', `${e}`);

export const getRandomString = (length = 20, number = true, capLetter = true, smallLetter = true) => {
    const randomChars = `${capLetter ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : ''}${smallLetter ? 'abcdefghijklmnopqrstuvwxyz' : ''}${number ? '0123456789' : ''}`;

    return Array(length).fill(0).map(() => randomChars.charAt(Math.round(Math.random() * randomChars.length))).join('');
}

export const IS_RAW_OBJECT = (e) => e && typeof e === 'object' && !Array.isArray(e);

export const IS_WHOLE_NUMBER = (v) => typeof v === 'number' && !`${v}`.includes('.');

export const queryEntries = (obj, lastPath = '', exceptions = []) => {
    let o = [];

    Object.entries(obj).forEach(([key, value]) => {
        if (typeof value === 'object' && value && !Array.isArray(value) && !exceptions.includes(key)) {
            o = [...o, ...queryEntries(value, `${lastPath}${key}.`)];
        } else o.push([`${lastPath}${key}`, value]);
    });

    return o;
}

export const niceTry = (promise) => new Promise(async resolve => {

    try {
        const r = await promise();
        resolve(r);
    } catch (e) {
        console.error('niceTry encounter an error: ', e);
        resolve();
    }
});