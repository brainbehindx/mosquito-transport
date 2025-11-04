import pkg from 'jsonwebtoken';
import { simplifyError } from 'simplify-error';
import { ADMIN_DB_NAME, ADMIN_DB_URL, EnginePath, ERRORS, REFRESH_TOKEN_EXPIRY, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables"
import { queryDocument, readDocument, writeDocument } from '../database';
import { setLargeTimeout, setLargeInterval } from "set-large-timeout";

const { sign, verify } = pkg;

export const verifyJWT = async (token, projectName, isRefreshToken) => new Promise((resolve, reject) => {
    verify(token, Scoped.InstancesData[projectName].signerKey, { ignoreExpiration: true }, (err, r) => {
        if (err) reject(err);
        else {
            if (isRefreshToken && !r.isRefreshToken) {
                reject(new Error('This token is valid but not a refresh token'));
            } else if (!isRefreshToken && r.isRefreshToken) {
                reject(new Error('This token is valid but not an access token'));
            } else {
                r.toString = () => token;
                resolve(r);
            }
        }
    });
});

export const signJWT = async (payload, projectName, isRefreshToken) => {
    const options = {
        exp: ((isRefreshToken ? REFRESH_TOKEN_EXPIRY : TOKEN_EXPIRY)(projectName) + Date.now()) / 1000,
        aud: projectName,
        iss: Scoped.InstancesData[projectName].externalAddress,
        sub: payload.uid
    };

    const { tokenID, uid } = payload;

    const [jwtToken, writtenReference] = await Promise.all([
        new Promise((resolve, reject) => {
            sign(
                { ...options, ...payload },
                Scoped.InstancesData[projectName].signerKey,
                undefined,
                async (err, token) => {
                    if (err) reject(err);
                    else resolve(token);
                }
            );
        }),
        isRefreshToken ?
            writeDocument({
                path: EnginePath.refreshTokenStore,
                value: {
                    createdOn: Date.now(),
                    uid,
                    _id: tokenID
                }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL) : Promise.resolve()
    ]);
    if (isRefreshToken && !writtenReference?.acknowledged)
        throw 'unacknowledged written token reference';

    return jwtToken;
};

export const validateJWT = async (token, projectName, isRefreshToken) => {
    try {
        const auth = await verifyJWT(token, projectName, isRefreshToken);
        const expiry = (auth.exp || 0) * 1000;
        let tokenData;

        if (auth && (
            Date.now() > expiry ||
            (isRefreshToken ?
                !(tokenData = await readDocument({
                    path: EnginePath.refreshTokenStore,
                    find: { _id: auth.tokenID }
                }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL))
                :
                Scoped.BlacklistedTokens?.[projectName]?.[auth.tokenID])
        )) {
            if (Date.now() > expiry) throw ERRORS.TOKEN_EXPIRED;
            throw ERRORS.TOKEN_NOT_FOUND;
        }

        if (tokenData && tokenData?.uid !== auth.uid)
            throw ERRORS.TOKEN_MOCKED;

        return auth;
    } catch (e) {
        if (!e.simpleError) throw simplifyError('invalid_auth_token', `${e}`);
        throw e;
    }
};

export const signRefreshToken = (payload, projectName) => signJWT(payload, projectName, true);
export const validateRefreshToken = async (token, projectName) => validateJWT(token, projectName, true);

// Token store manager
export const releaseTokenSelfDestruction = (projectName) => {
    const lifetime = REFRESH_TOKEN_EXPIRY(projectName);
    const interval = Math.round(lifetime * .25);

    const cleanUpTokens = async () => {
        await writeDocument({
            path: EnginePath.refreshTokenStore,
            find: { createdOn: { $lt: Date.now() - lifetime } },
            scope: 'deleteMany'
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

        const hotExpires = await queryDocument({
            path: EnginePath.refreshTokenStore,
            find: { createdOn: { $lt: Date.now() - (lifetime - interval) } }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

        hotExpires.forEach(e => {
            setLargeTimeout(() => {
                writeDocument({
                    path: EnginePath.refreshTokenStore,
                    find: { _id: e._id },
                    scope: 'deleteOne'
                }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
            }, Math.max(0, (e.createdOn + lifetime) - Date.now()));
        });
    };

    cleanUpTokens();
    setLargeInterval(cleanUpTokens, interval);

    queryDocument({
        path: EnginePath.revokedAccessToken,
        find: {}
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL).then(r => {
        r.forEach(e => {
            setBlacklistedTokenTimer(e._id, projectName, e.pop_on - Date.now());
        });
    });
};

export const destroyToken = async (ref, projectName, isRefreshToken) => {
    if (isRefreshToken)
        return writeDocument({
            path: EnginePath.refreshTokenStore,
            find: { _id: ref },
            scope: 'deleteOne'
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
            .then(r => !!r.deletedCount);

    if (Scoped.BlacklistedTokens[projectName]?.[ref]) return false;
    const lifetime = TOKEN_EXPIRY(projectName);

    writeDocument({
        path: EnginePath.revokedAccessToken,
        value: {
            _id: ref,
            pop_on: Date.now() + lifetime
        }
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
    setBlacklistedTokenTimer(ref, projectName, lifetime);
    return true;
};

const setBlacklistedTokenTimer = (ref, projectName, timeout) => {
    if (!Scoped.BlacklistedTokens[projectName])
        Scoped.BlacklistedTokens[projectName] = {};
    Scoped.BlacklistedTokens[projectName][ref] = true;

    setLargeTimeout(() => {
        writeDocument({
            path: EnginePath.revokedAccessToken,
            find: { _id: ref },
            scope: 'deleteOne'
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        if (Scoped.BlacklistedTokens[projectName]?.[ref])
            delete Scoped.BlacklistedTokens[projectName][ref];
    }, Math.max(0, timeout));
}