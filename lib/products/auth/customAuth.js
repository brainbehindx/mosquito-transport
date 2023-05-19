import EnginePath from "../../helpers/EnginePath";
import { getRandomString, simplifyError } from "../../helpers/utils"
import { ADMIN_DB_NAME, ADMIN_DB_URL, REGEX, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables";
import { readDocument, TIMESTAMP, writeDocument } from "../database";
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
            const h = await readDocument({ path: EnginePath.userAcct(), find: { email, password } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
            if (h) throw simplifyError('email_already_exists', 'This email address has already been taken');
        }

        const { verified, sub, metadata } = customExtras,
            newUid = `${Scoped.EnableSequentialUid[projectName] ? ++Scoped.SequentialUid[projectName] : getRandomString(30)}`,
            encryptionKey = getRandomString(),
            tokenData = {
                email,
                metadata: { ...metadata },
                signupMethod,
                joinedOn: Date.now(),
                encryptionKey,
                claims: {},
                emailVerified: signupMethod !== 'custom' && verified,
                profile
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
                path: EnginePath.userAcct(),
                value: {
                    ...tokenData,
                    ...(password ? { password } : {}),
                    ...(sub ? { [`${signupMethod}_sub`]: sub } : {}),
                    _id: newUid
                },
                scope: 'set'
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
            writeDocument({
                path: EnginePath.tokenStore(),
                value: {
                    $currentDate: {
                        createdOn: TIMESTAMP
                    },
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

        userData = await readDocument({ path: EnginePath.userAcct(), find: { email, password } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
        if (!userData) throw simplifyError('user_not_found', 'This user is not found on our database records');
    }

    const { metadata, signupMethod, joinedOn, encryptionKey, emailVerified, _id, profile, claims } = userData,
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
            profile
        },
        tokenID = getRandomString(30);

    const p = await Promise.all([
        signJWT({ ...tokenData, tokenID }, projectName),
        writeDocument({
            path: EnginePath.tokenStore(),
            value: {
                $currentDate: {
                    createdOn: TIMESTAMP
                },
                uid: _id,
                _id: tokenID
            }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
    ]);

    return { token: p[0], tokenData: { ...tokenData, expOn: TOKEN_EXPIRY() } };
}

export const refreshToken = async (token, projectName) => {
    const { tokenID, email, uid } = await verifyJWT(token, projectName),
        acct = await Promise.all([
            readDocument({ path: EnginePath.tokenStore(), find: { _id: tokenID } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL),
            readDocument({ path: EnginePath.userAcct(), find: { _id: uid } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        ]);

    if (!acct[0]) throw simplifyError('token_not_found', 'This token was not found in our records');
    if (!acct[1]) throw simplifyError('user_not_found', 'The user that owns this token is not found on our database records');

    const { metadata, signupMethod, joinedOn, encryptionKey, _id, claims, emailVerified, profile } = acct[1],
        tokenData = {
            email,
            metadata,
            signupMethod,
            joinedOn,
            encryptionKey,
            uid: _id,
            claims,
            emailVerified,
            profile
        },
        newTokenID = getRandomString(30);

    const p = await Promise.all([
        signJWT({ ...tokenData, tokenID: newTokenID }, projectName),
        writeDocument({
            path: EnginePath.tokenStore(),
            value: {
                $currentDate: {
                    createdOn: TIMESTAMP
                },
                uid: _id,
                _id: newTokenID
            }
        }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
    ]);

    return { token: p[0], tokenData: { ...tokenData, expOn: TOKEN_EXPIRY() } };
}

export const invalidateToken = (tokenID, projectName) => {
    return writeDocument({
        path: EnginePath.tokenStore(),
        value: null,
        find: { _id: tokenID },
        scope: 'delete'
    }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL);
}