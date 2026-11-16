import { Validator } from "guard-object";
import { UserCountReadyListener } from "../../helpers/listeners.js";
import { getRandomString } from "../../helpers/utils.js"
import { ADMIN_DB, AUTH_PROVIDER_ID, EnginePath, ERRORS } from "../../helpers/values.js";
import { Scoped } from "../../helpers/variables.js";
import { destroyToken, signJWT, signRefreshToken, validateRefreshToken, verifyJWT } from "./tokenizer.js";
import { simplifyError } from 'simplify-error';
import { hash, verify } from "argon2";
import { getDB } from "../database/base.js";

const PlatformList = new Set(["ios", "android", "macos", "windows", "web"]);

const validatePlatform = p => {
    if (!PlatformList.has(p))
        throw `invalid value supplied to platform, got '${p}' but expected any of ${[...PlatformList]}`;
}

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

    const { platform } = customExtras || {};

    validatePlatform(platform);

    try {
        if (Scoped.pendingSignups[processID]) throw ERRORS.CONCURRENT_SIGNUP;
        Scoped.pendingSignups[processID] = true;

        const { enableSequentialUid, uidLength, mergeAuthAccount, interceptNewAuth } = Scoped.InstancesData[projectName];
        let hashed_password;

        const doHash = async () => {
            if (hashed_password || !password) return hashed_password;
            return hashed_password = await hash(password);
        }

        if (signupMethod === AUTH_PROVIDER_ID.PASSWORD) {
            if (!password || typeof password !== 'string') throw ERRORS.PASSWORD_REQUIRED;
            if (!Validator.EMAIL(email)) throw ERRORS.INVALID_EMAIL;
            const prevData =
                await getDB(projectName, ADMIN_DB)
                    .collection(EnginePath.userAcct)
                    .find({ email })
                    .toArray();

            if (prevData.length) {
                if (prevData.find(v => v.password)) throw ERRORS.ACCOUNT_ALREADY_EXIST;

                if (mergeAuthAccount) {
                    await getDB(projectName, ADMIN_DB)
                        .collection(EnginePath.userAcct)
                        .updateOne({ _id: prevData[0]._id }, {
                            $set: { password: await doHash() }
                        });

                    return {
                        ...(await signinCustom(email, password, undefined, projectName, undefined, { platform })),
                        isNewUser: false
                    }
                }
            }
            await doHash();

            const aBuild = {
                email,
                password,
                ...hashed_password ? { hashed_password } : {},
                name: customExtras.name,
                request: customExtras.req,
                metadata: customExtras.metadata,
                method: AUTH_PROVIDER_ID.PASSWORD,
                platform
            };

            const {
                metadata = customExtras.metadata || {},
                profile,
                uid: d_uid,
                passwordVerified
            } = (await interceptNewAuth?.(aBuild)) || {};

            customExtras = {
                passwordVerified,
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
        const newUid =
            (d_uid && typeof d_uid === 'string')
                ? d_uid
                : enableSequentialUid
                    ? await getUserSequentialCount(projectName)
                    : getRandomString(uidLength || 30);
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
            disabled: false,
            signupWith: platform,
            platform
        };

        const [token, refreshToken, acctRes] =
            await Promise.all([
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
                getDB(projectName, ADMIN_DB)
                    .collection(EnginePath.userAcct)
                    .insertOne({
                        ...tokenData,
                        ...hashed_password ? { password: hashed_password } : {},
                        ...sub ? { [signupMethod]: sub } : {},
                        _id: newUid
                    })
            ]);

        if (!acctRes?.acknowledged) {
            await getDB(projectName, ADMIN_DB)
                .collection(EnginePath.refreshTokenStore)
                .deleteOne({ _id: refreshTokenID });

            throw ERRORS.UID_ALREADY_EXISTS(newUid);
        }

        return { token, refreshToken, isNewUser: true };
    } catch (e) {
        throw e;
    } finally {
        delete Scoped.pendingSignups[processID];
    }
};

export const signinCustom = async (
    email = '',
    password = '',
    signinMethod = AUTH_PROVIDER_ID.PASSWORD,
    projectName,
    defaultRecord,
    { platform }
) => {
    email = email.trim().toLowerCase();

    let userData = defaultRecord;

    validatePlatform(platform);

    if (signinMethod === AUTH_PROVIDER_ID.PASSWORD) {
        if (!password || typeof password !== 'string') throw ERRORS.PASSWORD_REQUIRED;
        if (!Validator.EMAIL(email)) ERRORS.INVALID_EMAIL;

        userData =
            await getDB(projectName, ADMIN_DB)
                .collection(EnginePath.userAcct)
                .find({ email })
                .toArray();

        if (userData.length) {
            let hasPassword;

            const passworded =
                await Promise.all(
                    userData.map(async v => {
                        if (!v.password) return v;
                        hasPassword = true;
                        const pass = await verify(v.password, password);
                        return { ...v, _passwork_hash_verified: pass };
                    })
                ).then(r =>
                    r.find(v => v._passwork_hash_verified)
                );

            if (hasPassword) {
                if (passworded) {
                    userData = passworded;
                } else throw ERRORS.INCORRECT_PASSWORD;
            } else throw ERRORS.ACCOUNT_NO_PASSWORD;
        } else throw ERRORS.USER_NOT_FOUND;
    }

    const { metadata, signupMethod, joinedOn, passwordVerified, _id, profile, claims, disabled, signupWith } = userData;
    const tokenID = getRandomString(30);
    const refreshTokenID = getRandomString(30);
    const tokenData = {
        email,
        metadata,
        signupMethod,
        currentAuthMethod: signinMethod,
        signupWith: signupWith || platform,
        platform,
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

    const [token, refreshToken] =
        await Promise.all([
            signJWT(bakeToken({ ...tokenData }), projectName),
            signRefreshToken({ uid: _id, tokenID: refreshTokenID, isRefreshToken: true }, projectName)
        ]);

    return { token, refreshToken };
};

export const refreshToken = async ({ token, refToken }, projectName, acrData, acrUser) => {
    const [{ uid, currentAuthMethod, lastLoginAt, entityOf, platform }, refAuth] =
        await Promise.all([
            acrUser ? Promise.resolve(acrUser) : verifyJWT(token, projectName),
            validateRefreshToken(refToken, projectName)
        ]);

    if (uid !== refAuth.uid) throw ERRORS.TOKEN_MISMATCH;
    if (entityOf !== refAuth.tokenID) throw ERRORS.ENTITY_MISMATCH;

    const userData =
        await getDB(projectName, ADMIN_DB)
            .collection(EnginePath.userAcct)
            .findOne({ _id: uid });

    if (!userData) throw ERRORS.TOKEN_USER_NOT_FOUND;

    const { metadata, signupMethod, joinedOn, _id, claims, passwordVerified, profile, disabled, email, signupWith } = userData;
    const newTokenID = getRandomString(30);
    const tokenData = {
        email,
        metadata,
        signupMethod,
        currentAuthMethod,
        signupWith,
        platform,
        joinedOn,
        uid: _id,
        claims,
        passwordVerified,
        profile,
        disabled,
        lastLoginAt,
        tokenID: newTokenID,
        entityOf: refAuth.tokenID,
        acr: acrUser ? acrData : refAuth.acr
    };

    const tokenPromise = signJWT(bakeToken({ ...tokenData }), projectName);
    const rtPromise =
        acrUser
            ? signJWT({
                uid: _id,
                tokenID: entityOf,
                isRefreshToken: true,
                exp: refAuth.exp,
                acr: tokenData.acr
            }, projectName)
            : undefined;

    return {
        token: await tokenPromise,
        ...rtPromise ? { refreshToken: await rtPromise } : {}
    };
};

export const upgradeToken = async (result, user, r_token, projectName) =>
    refreshToken({ refToken: r_token }, projectName, result, user);

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
    getDB(projectName, ADMIN_DB)
        .collection(EnginePath.refreshTokenStore)
        .deleteMany({ uid });

const getUserSequentialCount = (projectName) =>
    new Promise(resolve => {
        if (isNaN(Scoped.SequentialUid[projectName])) {
            const l = UserCountReadyListener.listenToPersist(projectName, () => {
                if (!isNaN(Scoped.SequentialUid[projectName])) {
                    resolve(++Scoped.SequentialUid[projectName]);
                    l();
                }
            });
        } else resolve(++Scoped.SequentialUid[projectName]);
    });