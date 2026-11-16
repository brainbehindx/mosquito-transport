import { guardObject, GuardSignal, niceGuard, Validator } from "guard-object";
import { Scoped } from "./variables.js";
import { ERRORS } from "./values.js";
import { normalizeRoute } from "./utils.js";
import { setLargeTimeout } from "set-large-timeout";

export const useDDOS = ({
    config,
    requestPath,
    route,
    req,
    ipNode
}) => {
    requestPath = normalizeRoute(requestPath);

    const skipRoute = route === null;
    const ipAddress = skipRoute ? '' : typeof ipNode === 'function' ? ipNode(req) : req[ipNode || 'ip'];

    const tipConfig = config?.[route];
    if (tipConfig || skipRoute) {
        const rootValue =
            skipRoute
                ? false
                : niceGuard(DDOS_guard, tipConfig)
                    ? tipConfig
                    : tipConfig?.[requestPath];

        if (rootValue || skipRoute) {
            const { calls, perSeconds } = skipRoute ? config : rootValue;
            const accessPath = `${skipRoute ? '' : ipAddress}-${route}-${requestPath}`;

            if (Scoped.DDOS_Verse[accessPath]) {
                if (++Scoped.DDOS_Verse[accessPath] > calls) {
                    throw ERRORS.TOO_MANY_REQUEST;
                }
            } else {
                Scoped.DDOS_Verse[accessPath] = 1;
                setLargeTimeout(() => {
                    if (Scoped.DDOS_Verse[accessPath])
                        delete Scoped.DDOS_Verse[accessPath];
                }, perSeconds * 1000);
            }
        }
    }
};

export const throwRateLimit = (node) =>
    (key, calls, perSeconds) => {
        if (typeof key !== 'string')
            throw new Error(`expected throwRateLimit first argument to be type of a string but got ${key}`);

        if (!Validator.POSITIVE_INTEGER(calls))
            throw new Error(`expected throwRateLimit second argument to be type of a positive integer but got ${calls}`);

        if (!Validator.POSITIVE_INTEGER(perSeconds))
            throw new Error(`expected throwRateLimit third argument to be type of a positive integer but got ${perSeconds}`);

        useDDOS({
            route: null,
            requestPath: `${node}:${key}-`,
            config: { calls, perSeconds }
        });
    };

export const statusErrorCode = (e) => {
    const code = {
        [ERRORS.TOO_MANY_REQUEST.simpleError.error]: 429
    }[e?.simpleError?.error];

    return code || 403;
};

const ddos_steps = [
    ['auth', ['signup', 'signin', 'signout', 'refresh_token', 'upgrade_token', 'google_signin', 'apple_signin']],
    ['database', ['read', 'query', 'write']],
    ['storage', ['get', 'upload', 'delete', 'delete_folder']],
    ['requests']
];

const DDOS_guard = {
    calls: GuardSignal.POSITIVE_INTEGER,
    perSeconds: GuardSignal.POSITIVE_INTEGER
};

export const validateDDOS_Config = (config) => {
    if (!Validator.OBJECT(config)) throw `expected an object for ddosMap but got ${config}`;
    guardObject({
        ...Object.fromEntries(
            ddos_steps.map(([k, v]) =>
                [k, k === 'requests' ? Validator.OBJECT(config?.requests) ? Object.keys(config.requests) : [] : v]
            ).map(([k, v]) =>
                [
                    k,
                    t => t === undefined ||
                        niceGuard(DDOS_guard, t) ||
                        guardObject(
                            Object.fromEntries(
                                v.map(r => [
                                    r,
                                    t => t === undefined ||
                                        niceGuard(DDOS_guard, t)
                                ])
                            )
                        ).validate(t)
                ]
            )
        )
    }).validate(config);
};