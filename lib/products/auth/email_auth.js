import { Validator } from "guard-object";
import { UserCountReadyListener } from "../../helpers/listeners";
import { getRandomString } from "../../helpers/utils"
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, EnginePath, ERRORS } from "../../helpers/values";
import { Scoped } from "../../helpers/variables";
import { queryDocument, readDocument, writeDocument } from "../database";
import { destroyToken, signJWT, signRefreshToken, validateRefreshToken, verifyJWT } from "./tokenizer";
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
    const processID = `${projectName}:${email}`;

    try {
        if (Scoped.pendingSignups[processID]) throw ERRORS.CONCURRENT_SIGNUP;
        Scoped.pendingSignups[processID] = true;

        const { enableSequentialUid, uidLength, mergeAuthAccount, interceptNewAuth } = Scoped.InstancesData[projectName];

        if (signupMethod === AUTH_PROVIDER_ID.PASSWORD) {
            if (!password || typeof password !== 'string') throw ERRORS.PASSWORD_REQUIRED;
            if (!Validator.EMAIL(email)) throw ERRORS.INVALID_EMAIL;
            const prevData = await queryDocument({
                path: EnginePath.userAcct,
                find: { email }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

            if (prevData.length) {
                if (prevData.find(v => v.password)) throw ERRORS.ACCOUNT_ALREADY_EXIST;

                if (mergeAuthAccount) {
                    await writeDocument({
                        find: { _id: prevData[0]._id },
                        value: { $set: { password } },
                        path: EnginePath.userAcct,
                        scope: 'updateOne'
                    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

                    return {
                        ...(await signinCustom(email, password, undefined, projectName)),
                        isNewUser: false
                    }
                }
            }
            const aBuild = {
                email,
                password,
                name: customExtras.name,
                request: customExtras.req,
                metadata: customExtras.metadata,
                method: AUTH_PROVIDER_ID.PASSWORD
            };

            const {
                metadata = customExtras.metadata || {},
                profile,
                uid: d_uid
            } = (await interceptNewAuth?.(aBuild)) || {};

            customExtras = {
                metadata: {
                    ...Validator.OBJECT(metadata) ? metadata : {}
                },
                profile: {
                    ...Validator.OBJECT(profile) ? profile : {}
                },
                d_uid
            };
        }

        const { sub, metadata, profile: profilex, d_uid, passwordVerified } = customExtras;
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
            passwordVerified: !!passwordVerified,
            profile: { ...profile, ...profilex },
            disabled: false
        };

        const [token, refreshToken, acctRes] = await Promise.all([
            signJWT(
                bakeToken({
                    ...tokenData,
                    entityOf: refreshTokenID,
                    uid: newUid,
                    tokenID,
                    lastLoginAt: Date.now(),
                    currentAuthMethod: signupMethod
                }),
                projectName
            ),
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
            await writeDocument({
                path: EnginePath.refreshTokenStore,
                find: { _id: refreshTokenID },
                scope: 'deleteOne'
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
            throw ERRORS.UID_ALREADY_EXISTS(newUid);
        }

        return { token, refreshToken, isNewUser: true };
    } catch (e) {
        throw e;
    } finally {
        delete Scoped.pendingSignups[processID];
    }
};

export const signinCustom = async (email = '', password = '', signinMethod = AUTH_PROVIDER_ID.PASSWORD, projectName, defaultRecord) => {
    email = email.trim().toLowerCase();

    let userData = defaultRecord;

    if (signinMethod === AUTH_PROVIDER_ID.PASSWORD) {
        if (!password || typeof password !== 'string') throw ERRORS.PASSWORD_REQUIRED;
        if (!Validator.EMAIL(email)) ERRORS.INVALID_EMAIL;

        userData = await queryDocument({
            path: EnginePath.userAcct,
            find: { email }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

        if (userData.length) {
            const passworded = userData.find(v => v.password === password) || userData.find(v => v.password);

            if (passworded) {
                if (passworded.password === password) {
                    userData = passworded;
                } else throw ERRORS.INCORRECT_PASSWORD;
            } else throw ERRORS.ACCOUNT_NO_PASSWORD;
        } else throw ERRORS.USER_NOT_FOUND;
    }

    const { metadata, signupMethod, joinedOn, passwordVerified, _id, profile, claims, disabled } = userData;
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
        passwordVerified,
        profile,
        disabled: !!disabled,
        tokenID,
        lastLoginAt: Date.now(),
        entityOf: refreshTokenID
    };

    if (disabled) throw ERRORS.ACCOUNT_DISABLED;

    const [token, refreshToken] = await Promise.all([
        signJWT(bakeToken({ ...tokenData }), projectName),
        signRefreshToken({ uid: _id, tokenID: refreshTokenID, isRefreshToken: true }, projectName)
    ]);

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

    const { metadata, signupMethod, joinedOn, _id, claims, passwordVerified, profile, disabled, email } = userData;
    const newTokenID = getRandomString(30);
    const tokenData = {
        email,
        metadata,
        signupMethod,
        currentAuthMethod,
        joinedOn,
        uid: _id,
        claims,
        passwordVerified,
        profile,
        disabled,
        lastLoginAt,
        tokenID: newTokenID,
        entityOf: refAuth.tokenID
    };

    // if (disabled) throw ERRORS.TOKEN_ACCOUNT_DISABLED;

    const tokenx = await signJWT(bakeToken({ ...tokenData }), projectName);

    return { token: tokenx };
};

function bakeToken(tokenData) {
    tokenData.authVerified = tokenData.currentAuthMethod !== AUTH_PROVIDER_ID.PASSWORD ||
        tokenData.passwordVerified;
    return tokenData;
}

export const invalidateToken = async (token, projectName, isRefreshToken) => {
    let data;

    try {
        data = await verifyJWT(token, projectName, isRefreshToken);
    } catch (e) {
        throw simplifyError('invalid_auth_token', `${e}`);
    }

    return destroyToken(data.tokenID, projectName, isRefreshToken);
};

export const cleanUserToken = (uid, projectName) =>
    writeDocument({
        path: EnginePath.refreshTokenStore,
        find: { uid },
        scope: 'deleteMany'
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

const getUserSequentialCount = (projectName) => new Promise(resolve => {
    if (isNaN(Scoped.SequentialUid[projectName])) {
        const l = UserCountReadyListener.listenToPersist(projectName, () => {
            if (!isNaN(Scoped.SequentialUid[projectName])) {
                resolve(++Scoped.SequentialUid[projectName]);
                l();
            }
        });
    } else resolve(++Scoped.SequentialUid[projectName]);
});