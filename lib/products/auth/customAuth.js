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
            if (!password)
                throw simplifyError('password_too_short', 'Password length must be greater than one');
            if (!REGEX.EMAIL_REGEX.test(email))
                throw simplifyError('invalid_email_format', 'Please provide a valid email format');
            const h = await readDocument({ path: EnginePath.userAcct, find: { email, password } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
            if (h) throw simplifyError('email_already_exists', 'This email address has already been taken');
        }

        const { verified, sub, metadata } = customExtras,
            newUid = `${Scoped.EnableSequentialUid[projectName] ? await getUserSequentialCount(projectName) : getRandomString(30)}`,
            encryptionKey = getRandomString(),
            tokenData = {
                email,
                metadata: { ...metadata },
                signupMethod,
                joinedOn: Date.now(),
                encryptionKey,
                claims: {},
                emailVerified: signupMethod !== 'custom' && verified,
                profile,
                disabled: false
            },
            tokenID = getRandomString(30),
            jwtData = {
                ...tokenData,
                currentAuthMethod: signupMethod,
                uid: newUid
            };

        const p = await Promise.all([
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

        return { token: p[0], tokenData: { ...jwtData, expOn: TOKEN_EXPIRY() } };
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
        if (!REGEX.EMAIL_REGEX.test(email)) throw simplifyError('invalid_email_format', 'Please provide a valid email format');

        userData = await readDocument({ path: EnginePath.userAcct, find: { email, password } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        if (!userData) throw simplifyError('user_not_found', 'This user is not found on our database records');
    }

    const { metadata, signupMethod, joinedOn, encryptionKey, emailVerified, _id, profile, claims, disabled } = userData,
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

    const p = await Promise.all([
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

    return { token: p[0], tokenData: { ...tokenData, expOn: TOKEN_EXPIRY() } };
}

export const refreshToken = async (token, projectName) => {
    const { tokenID, email, uid, currentAuthMethod } = await verifyJWT(token, projectName),
        acct = await Promise.all([
            readDocument({ path: EnginePath.tokenStore, find: { _id: tokenID } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
            readDocument({ path: EnginePath.userAcct, find: { _id: uid } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        ]);

    if (!acct[0]) throw simplifyError('token_not_found', 'This token was not found in our records');
    if (!acct[1]) throw simplifyError('user_not_found', 'The user that owns this token is not found on our database records');

    const { metadata, signupMethod, joinedOn, encryptionKey, _id, claims, emailVerified, profile, disabled } = acct[1],
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

    const p = await Promise.all([
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

    return { token: p[0], tokenData: { ...tokenData, expOn: TOKEN_EXPIRY() } };
}

export const invalidateToken = (tokenID, projectName) => {
    return writeDocument({
        path: EnginePath.tokenStore,
        find: { _id: tokenID },
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
    if (typeof Scoped.SequentialUid[projectName] === 'number') {
        resolve(++Scoped.SequentialUid[projectName]);
    } else {
        const l = UserCountReadyListener.startKeyListener(projectName, () => {
            if (typeof Scoped.SequentialUid[projectName] === 'number') {
                resolve(++Scoped.SequentialUid[projectName]);
                l();
            }
        }, true);
    }
});