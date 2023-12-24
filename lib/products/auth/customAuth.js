import EnginePath from "../../helpers/EnginePath";
import { UserCountReadyListener } from "../../helpers/listeners";
import { getRandomString, simplifyError } from "../../helpers/utils"
import { ADMIN_DB_NAME, ADMIN_DB_URL, REFRESH_TOKEN_EXPIRY, REGEX, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables";
import { queryDocument, readDocument, writeDocument } from "../database";
import { addTokenSelfDestruct, destroyToken, signJWT, signRefreshToken, validateRefreshToken, verifyJWT } from "./tokenizer";


export const signupCustom = async (email = '', password = '', signupMethod = 'custom', profile = {}, projectName, customExtras = {}) => {

    try {
        email = email.trim().toLowerCase();
        if (Scoped.pendingSignups[`${projectName}${email}`])
            throw simplifyError('currently_signup_elsewhere', 'This email address is currently being signup elsewhere');

        Scoped.pendingSignups[`${projectName}${email}`] = true;

        if (signupMethod === 'custom') {
            if (!password) throw simplifyError('password_too_short', 'Password length must be greater than one');
            if (!REGEX.EMAIL().test(email))
                throw simplifyError('invalid_email_format', 'Please provide a valid email format');

            const h = await readDocument({
                path: EnginePath.userAcct,
                find: { email }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
            if (h) throw simplifyError('email_already_exists', 'This email address has already been taken');
        }

        const { verified, sub, metadata, profile: profilex, d_uid } = customExtras,
            newUid = (d_uid && typeof d_uid === 'string') ? d_uid : (`${Scoped.InstancesData[projectName].enableSequentialUid ? await getUserSequentialCount(projectName) : getRandomString(Scoped.InstancesData[projectName].uidLength || 30)}`),
            tokenID = getRandomString(30),
            refreshTokenID = getRandomString(30),
            tokenData = {
                email,
                claims: {},
                metadata: { ...metadata },
                signupMethod,
                joinedOn: Date.now(),
                emailVerified: signupMethod !== 'custom' && verified,
                profile: { ...profile, ...profilex },
                disabled: false,
                currentAuthMethod: signupMethod
            };

        const [token, refreshToken, acctRes] = await Promise.all([
            signJWT({
                ...tokenData,
                uid: newUid,
                tokenID,
                lastLoginAt: Date.now()
            }, projectName),
            signRefreshToken({ uid: newUid, tokenID: refreshTokenID, isRefreshToken: true }, projectName),
            writeDocument({
                path: EnginePath.userAcct,
                value: {
                    ...tokenData,
                    ...(password ? { password } : {}),
                    ...(sub ? { [`${signupMethod}_sub`]: sub } : {}),
                    _id: newUid
                }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
            writeDocument({
                path: EnginePath.tokenStore,
                value: {
                    createdOn: Date.now(),
                    uid: newUid,
                    _id: tokenID
                }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
            writeDocument({
                path: EnginePath.refreshTokenStore,
                value: {
                    createdOn: Date.now(),
                    uid: newUid,
                    _id: refreshTokenID
                }
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        ]);

        if (!acctRes) {
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
            throw simplifyError('uid_already_exists', `This userId:${newUid} for this account has already been taken`);
        }

        addTokenSelfDestruct(tokenID, projectName, TOKEN_EXPIRY(projectName));
        addTokenSelfDestruct(refreshTokenID, projectName, REFRESH_TOKEN_EXPIRY(projectName), true);

        delete Scoped.pendingSignups[`${projectName}${email}`];

        return { token, refreshToken };
    } catch (e) {
        delete Scoped.pendingSignups[`${projectName}${email}`];
        throw e;
    }
}

export const signinCustom = async (email = '', password = '', signinMethod = 'custom', projectName, defaultRecord) => {
    email = email.trim().toLowerCase();

    let userData = defaultRecord;

    if (signinMethod === 'custom') {
        if (!password) throw simplifyError('password_too_short', 'Password length must be greater than one');
        if (!REGEX.EMAIL().test(email)) throw simplifyError('invalid_email_format', 'Please provide a valid email format');

        userData = await readDocument({
            path: EnginePath.userAcct,
            find: { email, password }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        if (!userData) throw simplifyError('user_not_found', 'This user is not found on our database records');
    }

    const { metadata, signupMethod, joinedOn, emailVerified, _id, profile, claims, disabled } = userData,
        tokenID = getRandomString(30),
        refreshTokenID = getRandomString(30),
        tokenData = {
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
            lastLoginAt: Date.now()
        };

    if (disabled) throw simplifyError('account_disable', 'You cannot sign into this account because it has been disabled');

    const [token, refreshToken] = await Promise.all([
        signJWT({ ...tokenData }, projectName),
        signRefreshToken({ uid: newUid, tokenID: refreshTokenID, isRefreshToken: true }, projectName),
        writeDocument({
            path: EnginePath.tokenStore,
            value: {
                createdOn: Date.now(),
                uid: _id,
                _id: tokenID
            }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
        writeDocument({
            path: EnginePath.refreshTokenStore,
            value: {
                createdOn: Date.now(),
                uid: _id,
                _id: refreshTokenID
            }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
    ]);

    addTokenSelfDestruct(tokenID, projectName, TOKEN_EXPIRY(projectName));
    addTokenSelfDestruct(refreshTokenID, projectName, REFRESH_TOKEN_EXPIRY(projectName), true);

    return { token, refreshToken };
}

export const refreshToken = async ({ token, refToken }, projectName) => {
    const [{ uid, currentAuthMethod, lastLoginAt }, refAuth] = await Promise.all([
        verifyJWT(token, projectName),
        validateRefreshToken(refToken, projectName)
    ]);

    if (uid !== refAuth.uid)
        throw simplifyError('token_mismatch', 'The accessToken and refreshToken are not meant for eachother');

    const userData = await readDocument({
        path: EnginePath.userAcct,
        find: { _id: uid }
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);

    if (!userData) throw simplifyError('user_not_found', 'The user that owns this token was not found on our database records');

    const { metadata, signupMethod, joinedOn, _id, claims, emailVerified, profile, disabled, email } = userData,
        newTokenID = getRandomString(30),
        tokenData = {
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
            tokenID: newTokenID
        };

    if (disabled) throw simplifyError('account_disabled', 'You cannot refresh token for this account because it has been disabled');

    const [tokenx] = await Promise.all([
        signJWT({ ...tokenData }, projectName),
        writeDocument({
            path: EnginePath.tokenStore,
            value: {
                createdOn: Date.now(),
                uid: _id,
                _id: newTokenID
            }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
    ]);

    addTokenSelfDestruct(newTokenID, projectName, TOKEN_EXPIRY(projectName));

    return { token: tokenx };
}

export const invalidateToken = async (token, projectName, isRefreshToken) => {
    let data;

    try {
        data = await verifyJWT(token, projectName, isRefreshToken);
    } catch (e) {
        throw simplifyError('invalid_auth_token', `${e}`);
    }

    return await destroyToken(data.tokenID, projectName, isRefreshToken);
}

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
}

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