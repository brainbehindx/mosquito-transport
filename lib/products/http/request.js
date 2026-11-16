import express from "express";
import { Scoped } from "../../helpers/variables.js";
import { normalizeRoute } from "../../helpers/utils.js";
import { validateJWT } from "../auth/tokenizer.js";
import { ERRORS, NO_CACHE_HEADER } from "../../helpers/values.js";
import { simplifyCaughtError } from 'simplify-error';
import { statusErrorCode, useDDOS } from "../../helpers/ddos.js";
import { deserialize } from "entity-serializer";
import { InternalRoutesList } from "../../zb-init.js";
import e2e_worker from "../../helpers/e2e_worker.js";

export function onApiRequest(route, callback, options, that) {
    if (typeof route !== 'string') throw `listenHttpsRequest first argument must be a string but got ${route}`;

    InternalRoutesList.forEach(e => {
        if (normalizeRoute(route) === normalizeRoute(e))
            throw `"${e}" is a reserved route used internally`;
    });

    const { logger } = that.config;
    const hasLogger = logger.includes('all') || logger.includes('external-requests');
    const hasErrorLogger = logger.includes('all') || logger.includes('error');

    Scoped.expressInstances[that.port].use(
        express.Router({ caseSensitive: true }).all(`/${normalizeRoute(route)}`, async (req, res) => {
            const { mtoken, uglified } = req.headers;
            const now = hasLogger && Date.now();

            if (hasLogger) console.log(`started route: /${req.url}`);
            res.set(NO_CACHE_HEADER);

            try {
                useDDOS(that.config.ddosMap, route, 'requests', req, that.config.ipNode);
            } catch (_) {
                res.setHeader(
                    'simple_error',
                    JSON.stringify(ERRORS.TOO_MANY_REQUEST.simpleError || {})
                );
                res.setHeader('Access-Control-Expose-Headers', 'simple_error');
                res.status(429).end('Too many request');
                return;
            }

            let auth;
            let authToken = mtoken;

            const assignAuth = async (nice) => {
                if (!authToken) return;
                try {
                    auth = await validateJWT(authToken, that.projectName);
                    if (auth && !auth.authVerified && !options?.allowUnverifiedAuth)
                        throw ERRORS.UNVERIFIED_AUTH;
                } catch (error) {
                    if (nice) return;
                    throw error;
                }
                if (!options?.allowDisabledAuth && auth.disabled)
                    throw ERRORS.DISABLED_AUTH_ACCESS;
            }

            if (options?.rawEntry) {
                try {
                    await assignAuth(true);
                    await callback(req, res, auth ? { ...auth, token: authToken } : null);
                } catch (e) {
                    if (hasErrorLogger) console.error(`errRoute: /${route} err: `, e);
                    res.setHeader(
                        'simple_error',
                        JSON.stringify(simplifyCaughtError(e).simpleError || {})
                    );
                    res.setHeader('Access-Control-Expose-Headers', 'simple_error');
                    if (!res.headersSent) res.end();
                }
                if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
                return;
            }

            let reqBody = req.body,
                clientPublicKey;

            try {
                // decrypt message
                if (that.config?.enforceE2E && !uglified)
                    throw ERRORS.ENCRYPTION_REQUIRED;

                if (uglified) {
                    const [body, clientKey, atoken] = await e2e_worker.decrypt(req.body, that.projectName);
                    clientPublicKey = clientKey;
                    authToken = atoken;
                    const initContentType = req.headers["init-content-type"];

                    if (initContentType === 'application/json') {
                        try {
                            reqBody = JSON.parse(body);
                        } catch (_) { }
                    } else reqBody = body;
                } else if (req.headers['entity-encoded'] === '1' && req.body) {
                    reqBody = deserialize(req.body);
                }

                req.body = reqBody;
                await assignAuth();
            } catch (e) {
                if (hasErrorLogger) console.error(`errRoute: /${route} err:`, e);

                res.setHeader(
                    'simple_error',
                    JSON.stringify(simplifyCaughtError(e).simpleError || {})
                );
                res.setHeader('Access-Control-Expose-Headers', 'simple_error');
                res.status(statusErrorCode(e)).end();
                return;
            }

            try {
                if (uglified) {
                    req.__sender = async (buffer) => {
                        res.set('content-type', 'application/octet-stream');
                        const buf = await e2e_worker.encrypt(buffer, clientPublicKey, that.projectName);
                        return buf;
                    };
                }

                await callback(req, res, auth ? { ...auth, token: authToken } : null);
            } catch (e) {
                if (hasErrorLogger) console.error(`errRoute: /${route} err:`, e);
                if (!res.headersSent) {
                    res.setHeader(
                        'simple_error',
                        JSON.stringify(simplifyCaughtError(e).simpleError || {})
                    );
                    res.setHeader('Access-Control-Expose-Headers', 'simple_error');
                    res.end();
                }
            }
            if (hasLogger) console.log(`${req.url} took: ${Date.now() - now}ms`);
        })
    );
};