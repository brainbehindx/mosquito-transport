import EnginePath from "../../helpers/EnginePath";
import { UserCountReadyListener } from "../../helpers/listeners";
import { getRandomString, simplifyError } from "../../helpers/utils"
import { ADMIN_DB_NAME, ADMIN_DB_URL, REGEX, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables";
import { readDocument, writeDocument } from "../database";
import { signJWT, verifyJWT } from "./tokenizer";

export const signupCustom = async (email = '', password = '', signupMethod = 'custom', profile = {}, projectName, customExtras = {}) => {

    try {
        email = email.trim().toLowerCase();
        if (Scoped.pendingSignups[`${projectName}${email}`])
            throw simplifyError('currently_signup_elsewhere', 'This email address is currently being signup elsewhere');

        Scoped.pendingSignups[`${projectName}${email}`] = true;

        if (signupMethod === 'custom') {
            if (!password) throw simplifyError('password_too_short', 'Password length must be greater than one');
            if (!REGEX.EMAIL_REGEX().test(email))
                throw simplifyError('invalid_email_format', 'Please provide a valid email format');
            const h = await readDocument({ path: EnginePath.userAcct, find: { email } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
            if (h) throw simplifyError('email_already_exists', 'This email address has already been taken');
        }

        const { verified, sub, metadata, profile: profilex, d_uid } = customExtras,
            newUid = d_uid || `${Scoped.EnableSequentialUid[projectName] ? await getUserSequentialCount(projectName) : getRandomString(Scoped.UidLength[projectName] || 30)}`,
            tokenData = {
                email,
                claims: {},
                metadata: { ...metadata },
                signupMethod,
                joinedOn: Date.now(),
                emailVerified: signupMethod !== 'custom' && verified,
                profile: { ...profile, ...profilex },
                disabled: false
            },
            tokenID = getRandomString(30),
            encryptionKey = getRandomString(30),
            jwtData = {
                ...tokenData,
                encryptionKey,
                currentAuthMethod: signupMethod,
                uid: newUid
            };

        const [tokenx] = await Promise.all([
            signJWT({ ...jwtData, tokenID }, projectName),
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
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        ]);

        delete Scoped.pendingSignups[`${projectName}${email}`];

        return { token: tokenx, tokenData: { ...jwtData, expOn: TOKEN_EXPIRY(projectName) } };
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
        if (!REGEX.EMAIL_REGEX().test(email)) throw simplifyError('invalid_email_format', 'Please provide a valid email format');

        userData = await readDocument({ path: EnginePath.userAcct, find: { email, password } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        if (!userData) throw simplifyError('user_not_found', 'This user is not found on our database records');
    }

    const { metadata, signupMethod, joinedOn, emailVerified, _id, profile, claims, disabled } = userData,
        encryptionKey = getRandomString(30),
        tokenData = {
            email,
            metadata,
            signupMethod,
            currentAuthMethod: signinMethod,
            joinedOn,
            encryptionKey,
            uid: _id,
            claims,
            emailVerified,
            profile,
            disabled: !!disabled
        },
        tokenID = getRandomString(30);

    if (disabled) throw simplifyError('account_disable', 'You cannot sign into this account because it has been disabled');

    const [tokenx] = await Promise.all([
        signJWT({ ...tokenData, tokenID }, projectName),
        writeDocument({
            path: EnginePath.tokenStore,
            value: {
                createdOn: Date.now(),
                uid: _id,
                _id: tokenID
            }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
    ]);

    return { token: tokenx, tokenData: { ...tokenData, expOn: TOKEN_EXPIRY(projectName) } };
}

export const refreshToken = async (token, projectName) => {
    const { tokenID, email, uid, currentAuthMethod } = await verifyJWT(token, projectName),
        acct = await Promise.all([
            readDocument({ path: EnginePath.tokenStore, find: { _id: tokenID } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
            readDocument({ path: EnginePath.userAcct, find: { _id: uid } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        ]);

    if (!acct[0]) throw simplifyError('token_not_found', 'This token was not found in our records');
    if (!acct[1]) throw simplifyError('user_not_found', 'The user that owns this token is not found on our database records');

    const { metadata, signupMethod, joinedOn, _id, claims, emailVerified, profile, disabled } = acct[1],
        encryptionKey = getRandomString(30),
        tokenData = {
            email,
            metadata,
            signupMethod,
            currentAuthMethod,
            joinedOn,
            encryptionKey,
            uid: _id,
            claims,
            emailVerified,
            profile,
            disabled
        },
        newTokenID = getRandomString(30);

    if (disabled) throw simplifyError('account_disable', 'You cannot refresh token for this account because it has been disabled');

    const [tokenx] = await Promise.all([
        signJWT({ ...tokenData, tokenID: newTokenID }, projectName),
        writeDocument({
            path: EnginePath.tokenStore,
            value: {
                createdOn: Date.now(),
                uid: _id,
                _id: newTokenID
            }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
    ]);

    return { token: tokenx, tokenData: { ...tokenData, expOn: TOKEN_EXPIRY(projectName) } };
}

export const invalidateToken = async (token, projectName) => {
    let data;

    try {
        data = await verifyJWT(token, projectName);
    } catch (e) {
        throw simplifyError('invalid_auth_token', `${e}`);
    }

    return await writeDocument({
        path: EnginePath.tokenStore,
        find: { _id: data.tokenID },
        scope: 'delete'
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
}

export const cleanUserToken = (uid, projectName) => {
    return writeDocument({
        path: EnginePath.tokenStore,
        find: { uid },
        scope: 'deleteMany'
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
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