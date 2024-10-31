import { Validator } from "guard-object";
import { UserCountReadyListener } from "../../helpers/listeners";
import { getRandomString } from "../../helpers/utils"
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, EnginePath, ERRORS, REFRESH_TOKEN_EXPIRY, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables";
import { queryDocument, readDocument, writeDocument } from "../database";
import { addTokenSelfDestruct, destroyToken, signJWT, signRefreshToken, validateRefreshToken, verifyJWT } from "./tokenizer";
import { simplifyError } from 'simplify-error';

export const signupCustom = async (
    email = '',
    password = '',
    signupMethod = AUTH_PROVIDER_ID.PASSWORD,
    profile = {},
    projectName,
    customExtras = {}
) => {
    email = email.trim().toLowerCase();
    const processID = `${projectName}${email}`;

    try {
        if (Scoped.pendingSignups[processID]) throw ERRORS.CONCURRENT_SIGNUP;
        Scoped.pendingSignups[processID] = true;

        if (signupMethod === AUTH_PROVIDER_ID.PASSWORD) {
            if (!password) throw ERRORS.PASSWORD_REQUIRED;
            if (!Validator.EMAIL(email)) throw ERRORS.INVALID_EMAIL;

            if (
                !(await readDocument({
                    path: EnginePath.userAcct,
                    find: { email }
                }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL))
            ) throw ERRORS.EMAIL_ALREADY_EXIST;
        }
        const { enableSequentialUid, uidLength } = Scoped.InstancesData[projectName];

        const { verified, sub, metadata, profile: profilex, d_uid } = customExtras;
        const newUid = (d_uid && typeof d_uid === 'string') ? d_uid :
            enableSequentialUid ? await getUserSequentialCount(projectName) :
                getRandomString(uidLength || 30);
        const tokenID = getRandomString(30);
        const refreshTokenID = getRandomString(30);
        const tokenData = {
            email,
            claims: {},
            metadata: { ...metadata },
            signupMethod,
            joinedOn: Date.now(),
            emailVerified: signupMethod !== AUTH_PROVIDER_ID.PASSWORD && verified,
            profile: { ...profile, ...profilex },
            disabled: false
        };

        const [token, refreshToken, acctRes] = await Promise.all([
            signJWT({
                ...tokenData,
                entityOf: refreshTokenID,
                uid: newUid,
                tokenID,
                lastLoginAt: Date.now(),
                currentAuthMethod: signupMethod
            }, projectName),
            signRefreshToken({
                uid: newUid,
                tokenID: refreshTokenID,
                isRefreshToken: true
            }, projectName),
            writeDocument({
                path: EnginePath.userAcct,
                value: {
                    ...tokenData,
                    ...password ? { password } : {},
                    ...sub ? { [signupMethod]: sub } : {},
                    _id: newUid
                }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        ]);

        if (!acctRes?.acknowledged) {
            await Promise.all([
                writeDocument({
                    path: EnginePath.tokenStore,
                    find: { _id: tokenID },
                    scope: 'deleteOne'
                }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
                writeDocument({
                    path: EnginePath.refreshTokenStore,
                    find: { _id: refreshTokenID },
                    scope: 'deleteOne'
                }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
            ]);
            throw ERRORS.UID_ALREADY_EXISTS(newUid);
        }

        addTokenSelfDestruct(tokenID, projectName, TOKEN_EXPIRY(projectName));
        addTokenSelfDestruct(refreshTokenID, projectName, REFRESH_TOKEN_EXPIRY(projectName), true);

        delete Scoped.pendingSignups[processID];

        return { token, refreshToken };
    } catch (e) {
        delete Scoped.pendingSignups[processID];
        throw e;
    }
};

export const signinCustom = async (email = '', password = '', signinMethod = AUTH_PROVIDER_ID.PASSWORD, projectName, defaultRecord) => {
    email = email.trim().toLowerCase();

    let userData = defaultRecord;

    if (signinMethod === AUTH_PROVIDER_ID.PASSWORD) {
        if (!password) throw ERRORS.PASSWORD_REQUIRED;
        if (!Validator.EMAIL(email)) ERRORS.INVALID_EMAIL;

        userData = await queryDocument({
            path: EnginePath.userAcct,
            find: { email }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

        if (userData.length) {
            const passworded = userData.find(v => v.password);
            if (passworded) {
                if (passworded.password === password) {
                    userData = passworded;
                } else throw ERRORS.INCORRECT_PASSWORD;
            } else throw ERRORS.ACCOUNT_NO_PASSWORD;
        } else throw ERRORS.USER_NOT_FOUND;
    }

    const { metadata, signupMethod, joinedOn, emailVerified, _id, profile, claims, disabled } = userData;
    const tokenID = getRandomString(30);
    const refreshTokenID = getRandomString(30);
    const tokenData = {
        email,
        metadata,
        signupMethod,
        currentAuthMethod: signinMethod,
        joinedOn,
        uid: _id,
        claims,
        emailVerified,
        profile,
        disabled: !!disabled,
        tokenID,
        lastLoginAt: Date.now(),
        entityOf: refreshTokenID
    };

    if (disabled) throw ERRORS.ACCOUNT_DISABLED;

    const [token, refreshToken] = await Promise.all([
        signJWT({ ...tokenData }, projectName),
        signRefreshToken({ uid: _id, tokenID: refreshTokenID, isRefreshToken: true }, projectName)
    ]);

    addTokenSelfDestruct(tokenID, projectName, TOKEN_EXPIRY(projectName));
    addTokenSelfDestruct(refreshTokenID, projectName, REFRESH_TOKEN_EXPIRY(projectName), true);

    return { token, refreshToken };
};

export const refreshToken = async ({ token, refToken }, projectName) => {
    const [{ uid, currentAuthMethod, lastLoginAt, entityOf }, refAuth] = await Promise.all([
        verifyJWT(token, projectName),
        validateRefreshToken(refToken, projectName)
    ]);

    if (uid !== refAuth.uid) throw ERRORS.TOKEN_MISMATCH;
    if (entityOf !== refAuth.tokenID) throw ERRORS.ENTITY_MISMATCH;

    const userData = await readDocument({
        path: EnginePath.userAcct,
        find: { _id: uid }
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

    if (!userData) throw ERRORS.TOKEN_USER_NOT_FOUND;

    const { metadata, signupMethod, joinedOn, _id, claims, emailVerified, profile, disabled, email } = userData;
    const newTokenID = getRandomString(30);
    const tokenData = {
        email,
        metadata,
        signupMethod,
        currentAuthMethod,
        joinedOn,
        uid: _id,
        claims,
        emailVerified,
        profile,
        disabled,
        lastLoginAt,
        tokenID: newTokenID,
        entityOf: refAuth.tokenID
    };

    if (disabled) throw ERRORS.TOKEN_ACCOUNT_DISABLED;

    const tokenx = await signJWT({ ...tokenData }, projectName);

    addTokenSelfDestruct(newTokenID, projectName, TOKEN_EXPIRY(projectName));

    return { token: tokenx };
};

export const invalidateToken = async (token, projectName, isRefreshToken) => {
    let data;

    try {
        data = await verifyJWT(token, projectName, isRefreshToken);
    } catch (e) {
        throw simplifyError('invalid_auth_token', `${e}`);
    }

    return await destroyToken(data.tokenID, projectName, isRefreshToken);
};

export const cleanUserToken = (uid, projectName) => {
    return Promise.all([
        queryDocument({
            path: EnginePath.tokenStore,
            find: { uid }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL).then(r =>
            Promise.all(r.map(({ _id }) =>
                destroyToken(_id, projectName)
            ))
        ),
        queryDocument({
            path: EnginePath.refreshTokenStore,
            find: { uid }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL).then(r =>
            Promise.all(r.map(({ _id }) =>
                destroyToken(_id, projectName, true)
            ))
        )
    ]);
};

const getUserSequentialCount = (projectName) => new Promise(resolve => {
    if (isNaN(Scoped.SequentialUid[projectName])) {
        const l = UserCountReadyListener.listenTo(projectName, () => {
            if (!isNaN(Scoped.SequentialUid[projectName])) {
                resolve(++Scoped.SequentialUid[projectName]);
                l();
            }
        }, true);
    } else resolve(++Scoped.SequentialUid[projectName]);
});