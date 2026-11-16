import pkg from 'jsonwebtoken';
import { simplifyError } from 'simplify-error';
import { ADMIN_DB, EnginePath, ERRORS, REFRESH_TOKEN_EXPIRY, TOKEN_EXPIRY } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js"
import { emitDatabase } from '../database/index.js';
import { setLargeTimeout, setLargeInterval } from "set-large-timeout";
import { getDB } from '../database/base.js';

const { sign, verify } = pkg;

export const verifyJWT = async (token, projectName, isRefreshToken) =>
    new Promise((resolve, reject) => {
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

    const [jwtToken, writtenReference] =
        await Promise.all([
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
            isRefreshToken
                ? getDB(projectName, ADMIN_DB)
                    .collection(EnginePath.refreshTokenStore)
                    .insertOne({
                        createdOn: Date.now(),
                        uid,
                        _id: tokenID
                    })
                : Promise.resolve()
        ]);
    if (isRefreshToken && !writtenReference?.acknowledged)
        throw 'unacknowledged written token reference';

    return jwtToken;
};

export const validateJWT = async (token, projectName, isRefreshToken) => {
    try {
        const crossCheckToken = Scoped.InstancesData[projectName].enableStatefulAccessToken;
        const auth = await verifyJWT(token, projectName, isRefreshToken);
        const expiry = (auth.exp || 0) * 1000;
        let tokenData;

        if (auth && (
            Date.now() > expiry ||
            (isRefreshToken ?
                !(tokenData =
                    await getDB(projectName, ADMIN_DB)
                        .collection(EnginePath.refreshTokenStore)
                        .findOne({ _id: auth.tokenID }))
                :
                (Scoped.BlacklistedTokens?.[projectName]?.[auth.tokenID] ||
                    (crossCheckToken &&
                        !(tokenData =
                            await getDB(projectName, ADMIN_DB)
                                .collection(EnginePath.refreshTokenStore)
                                .findOne({ _id: auth.entityOf }))
                    )
                )
            )
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
export const releaseTokenSelfDestruction = (projectName, shouldPurge) => {
    if (shouldPurge) {
        const lifetime = REFRESH_TOKEN_EXPIRY(projectName);
        const interval = Math.round(lifetime * .25);

        const cleanUpTokens = async () => {
            await getDB(projectName, ADMIN_DB)
                .collection(EnginePath.refreshTokenStore)
                .deleteMany({ createdOn: { $lt: Date.now() - lifetime } });

            const hotExpires =
                await getDB(projectName, ADMIN_DB)
                    .collection(EnginePath.refreshTokenStore)
                    .find({ createdOn: { $lt: Date.now() - (lifetime - interval) } })
                    .toArray();

            hotExpires.forEach(e => {
                setLargeTimeout(() => {
                    getDB(projectName, ADMIN_DB)
                        .collection(EnginePath.refreshTokenStore)
                        .deleteOne({ _id: e._id });
                }, Math.max(0, (e.createdOn + lifetime) - Date.now()));
            });
        };

        cleanUpTokens();
        setLargeInterval(cleanUpTokens, interval);
    }

    getDB(projectName, ADMIN_DB)
        .collection(EnginePath.revokedAccessToken)
        .find({})
        .toArray()
        .then(r => {
            r.forEach(e => {
                setBlacklistedTokenTimer(e._id, projectName, e.pop_on - Date.now(), shouldPurge);
            });
        });


    return emitDatabase(EnginePath.revokedAccessToken, e => {
        if (e.insertion) {
            e = e.insertion;
            setBlacklistedTokenTimer(e._id, projectName, e.pop_on - Date.now(), shouldPurge);
        } else if (e.deletion) {
            if (Scoped.BlacklistedTokens[projectName]?.[e.deletion])
                delete Scoped.BlacklistedTokens[projectName][e.deletion];
        }
    }, projectName, undefined, ADMIN_DB);
};

export const destroyToken = async (ref, projectName, isRefreshToken) => {
    if (isRefreshToken)
        return getDB(projectName, ADMIN_DB)
            .collection(EnginePath.refreshTokenStore)
            .deleteOne({ _id: ref })
            .then(r => !!r.deletedCount);

    if (Scoped.BlacklistedTokens[projectName]?.[ref]) return false;
    const lifetime = TOKEN_EXPIRY(projectName);

    return getDB(projectName, ADMIN_DB)
        .collection(EnginePath.revokedAccessToken)
        .insertOne({
            _id: ref,
            pop_on: Date.now() + lifetime
        })
        .catch(() => 0)
        .then(r => !!r?.acknowledged);
};

const setBlacklistedTokenTimer = (ref, projectName, timeout, shouldPurge) => {
    timeout = Math.max(0, timeout);

    if (timeout) {
        if (!Scoped.BlacklistedTokens[projectName])
            Scoped.BlacklistedTokens[projectName] = {};
        Scoped.BlacklistedTokens[projectName][ref] = true;
    }

    if (shouldPurge)
        setLargeTimeout(() => {
            getDB(projectName, ADMIN_DB)
                .collection(EnginePath.revokedAccessToken)
                .deleteOne({ _id: ref });

            if (Scoped.BlacklistedTokens[projectName]?.[ref])
                delete Scoped.BlacklistedTokens[projectName][ref];
        }, timeout);
}