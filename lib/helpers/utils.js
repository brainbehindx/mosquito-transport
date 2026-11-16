import { Buffer } from 'buffer';
import { dirname } from 'path';
import { mkdir } from 'fs/promises';
import fetch from "node-fetch";

export const getRandomString = (length = 20, number = true, capLetter = true, smallLetter = true) => {
    const randomChars = `${capLetter ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : ''}${number ? '0123456789' : ''}${smallLetter ? 'abcdefghijklmnopqrstuvwxyz' : ''}`;
    const indexSize = randomChars.length - 1;

    return Array(length).fill(0).map(() => randomChars.charAt(Math.round(Math.random() * indexSize))).join('');
};

export const normalizeRoute = (route = '') =>
    route
        .split('')
        .map((v, i, a) =>
            ((!i && v === '/') || (i === a.length - 1 && v === '/') || (i && a[i - 1] === '/' && v === '/')) ? '' : v
        ).join('');

export const ensureDir = async (filepath) => {
    filepath = `/${normalizeRoute(filepath)}`;
    await niceMkdir(dirname(filepath));
    return filepath;
};

const niceMkdir = async dir => {
    try {
        await mkdir(dir, { recursive: true, force: true });
    } catch (_) { }
};

export const niceTry = (promise) => new Promise(async resolve => {

    try {
        const r = await promise();
        resolve(r);
    } catch (e) {
        console.error('niceTry encounter an error: ', e);
        resolve();
    }
});

export const getStringExtension = (url) => {
    const r = url.split(/[#?]/)[0].split(".").pop().trim();
    return r === url ? '' : r;
};

export const interpolate = (x, [y1, x1], [y2, x2]) => {
    return y1 + ((x - x1) * ((y2 - y1) / (x2 - x1)));
};

export const encodeBinary = (s) => Buffer.from(s, 'utf8').toString('base64');
export const decodeBinary = (s) => Buffer.from(s, 'base64').toString('utf8');

/**
 * @param {URL | import("node-fetch").RequestInfo} url 
 * @param {import("node-fetch").RequestInit} option 
 * @param {number} timeout
 */
export const timeoutFetch = async (url, option, timeout = 60000) => {
    const signal = new AbortController();

    const timer = setTimeout(() => {
        signal.abort();
    }, timeout);

    const r = await fetch(url, { ...option, signal: signal.signal }).then(async h => {
        const response = new Response(await h.arrayBuffer(), {
            headers: h.headers,
            status: h.status,
            statusText: h.statusText
        });
        return response;
    });
    clearTimeout(timer);
    return r;
};