import pkg from 'jsonwebtoken';
import { simplifyError } from 'simplify-error';
import { ADMIN_DB_NAME, ADMIN_DB_URL, EnginePath, REFRESH_TOKEN_EXPIRY, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables"
import { queryDocument, readDocument, writeDocument } from '../database';
import setLargeTimeout from "set-large-timeout";

const { sign, verify } = pkg;

export const verifyJWT = async (token, projectName, isRefreshToken) => new Promise((resolve, reject) => {
    verify(token, Scoped.InstancesData[projectName].signerKey, { ignoreExpiration: true }, (err, r) => {
        if (err) reject(err);
        else {
            if (isRefreshToken && !r.isRefreshToken) {
                reject(new Error('This token is valid but not a refresh token'));
            } else if (!isRefreshToken && r.isRefreshToken) {
                reject(new Error('This token is valid but not an access token'));
            } else resolve(r);
        }
    });
});

export const signJWT = (payload, projectName, isRefreshToken) => new Promise((resolve, reject) => {
    const options = {
        exp: ((isRefreshToken ? REFRESH_TOKEN_EXPIRY : TOKEN_EXPIRY)(projectName) + Date.now()) / 1000,
        aud: projectName,
        iss: Scoped.InstancesData[projectName].externalAddress,
        sub: payload.uid
    };

    sign(
        { ...options, ...payload },
        Scoped.InstancesData[projectName].signerKey,
        undefined,
        (err, token) => {
            if (err) reject(err);
            else resolve(token);
        }
    );
});

export const validateJWT = async (token, projectName, isRefreshToken) => {
    try {
        const auth = await verifyJWT(token, projectName, isRefreshToken),
            expiry = (auth.exp || 0) * 1000;
        let tokenData;

        if (auth && (
            Date.now() > expiry ||
            !(tokenData = await readDocument({
                path: EnginePath[isRefreshToken ? 'refreshTokenStore' : 'tokenStore'],
                find: { _id: auth.tokenID }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL))
        )) {
            if (Date.now() > expiry) throw simplifyError('token_expired', 'The provided token has already expired');
            throw simplifyError('token_not_found', 'This token was not found in our records');
        }

        if (tokenData && tokenData?.uid !== auth.uid)
            throw simplifyError('token_mismatch', 'This token has been tempered with or probably mocked');

        return auth;
    } catch (e) {
        if (!e.simpleError) throw simplifyError('invalid_auth_token', `${e}`);
        throw e;
    }
}

export const signRefreshToken = (payload, projectName) => signJWT(payload, projectName, true);
export const validateRefreshToken = async (token, projectName) => validateJWT(token, projectName, true);

// Token store manager

export const releaseTokenSelfDestruction = (projectName) => {
    queryDocument({
        path: EnginePath.tokenStore,
        find: {}
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL).then(r => {

        r.forEach(v => {
            addTokenSelfDestruct(
                v._id,
                projectName,
                (v.createdOn + TOKEN_EXPIRY(projectName)) - Date.now()
            );
        });
    });
    queryDocument({
        path: EnginePath.refreshTokenStore,
        find: {}
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL).then(r => {

        r.forEach(v => {
            addTokenSelfDestruct(
                v._id,
                projectName,
                (v.createdOn + REFRESH_TOKEN_EXPIRY(projectName)) - Date.now(),
                true
            );
        });
    });
}

export const addTokenSelfDestruct = (ref, projectName, timeout, isRefreshToken) => {
    if (!Scoped.TokenSelfDestruction[isRefreshToken ? 'RefreshToken' : 'AccessToken'][projectName])
        Scoped.TokenSelfDestruction[isRefreshToken ? 'RefreshToken' : 'AccessToken'][projectName] = {};

    Scoped.TokenSelfDestruction[isRefreshToken ? 'RefreshToken' : 'AccessToken'][projectName][ref] = setLargeTimeout(() => {
        destroyToken(ref, projectName, isRefreshToken);
    }, timeout);
}

export const destroyToken = (ref, projectName, isRefreshToken) => {
    if (Scoped.TokenSelfDestruction[isRefreshToken ? 'RefreshToken' : 'AccessToken']?.[projectName]?.[ref] !== undefined) {
        Scoped.TokenSelfDestruction[isRefreshToken ? 'RefreshToken' : 'AccessToken'][projectName][ref]();
        delete Scoped.TokenSelfDestruction[isRefreshToken ? 'RefreshToken' : 'AccessToken'][projectName][ref];
    }

    return writeDocument({
        path: EnginePath[isRefreshToken ? 'refreshTokenStore' : 'tokenStore'],
        find: { _id: ref },
        scope: 'deleteOne'
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
}