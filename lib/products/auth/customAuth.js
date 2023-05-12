import EnginePath from "../../helpers/EnginePath";
import { getRandomString, simplifyError } from "../../helpers/utils"
import { REGEX, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables";
import { readDocument, TIMESTAMP, writeDocument } from "../database";
import { signJWT, verifyJWT } from "./tokenizer";

export const signupCustom = async (email = '', password = '', extras = {}, signupMethod = 'custom', profile = {}, projectName) => {
    email = email.trim().toLowerCase();
    if (Scoped.pendingSignups[`${projectName}${email}`]) throw simplifyError('currently_signup_elsewhere', 'This email address is currently being signup elsewhere');
    if (!password) throw simplifyError('password_too_short', 'Password length must be greater than one');
    if (!REGEX.EMAIL_REGEX.test(email)) throw simplifyError('invalid_email_format', 'Please provide a valid email format');
    Scoped.pendingSignups[`${projectName}${email}`] = true;

    const h = await readDocument({ path: EnginePath.userAcct(), find: { email } }, projectName);

    if (h) throw simplifyError('email_already_exists', 'This email address has already been taken');

    const newUid = `${Scoped.EnableSequentialUid[projectName] ? ++Scoped.SequentialUid[projectName] : getRandomString(30)}`,
        encryptionKey = getRandomString(),
        tokenData = {
            email,
            extras,
            signupMethod,
            joinedOn: Date.now(),
            encryptionKey,
            uid: newUid,
            claims: {},
            emailVerified: signupMethod !== 'custom',
            profile
        },
        tokenID = getRandomString(30);

    const p = await Promise.all([
        signJWT({ ...tokenData, tokenID }, projectName),
        writeDocument({
            path: EnginePath.userAcct(),
            value: {
                encryptionKey,
                email,
                password,
                extras,
                profile,
                claims: {},
                signupMethod,
                $currentDate: {
                    joinedOn: TIMESTAMP
                },
                emailVerified: signupMethod !== 'custom',
                _id: newUid
            },
            scope: 'set'
        }, projectName),
        writeDocument({
            path: EnginePath.tokenStore(),
            value: {
                $currentDate: {
                    createdOn: TIMESTAMP
                },
                uid: newUid,
                _id: tokenID
            }
        }, projectName)
    ]);

    delete Scoped.pendingSignups[`${projectName}${email}`];

    return { token: p[0], tokenData: { ...tokenData, expOn: TOKEN_EXPIRY() } };
}

export const signinCustom = async (email = '', password = '', signinMethod = 'custom', projectName) => {
    email = email.trim().toLowerCase();

    if (!password) throw simplifyError('password_too_short', 'Password length must be greater than one');
    if (!REGEX.EMAIL_REGEX.test(email)) throw simplifyError('invalid_email_format', 'Please provide a valid email format');

    const a = await readDocument({ path: EnginePath.userAcct(), find: { email, password } }, ADMIN_DB_NAME, ADMIN_DB_URL);

    if (!a) throw simplifyError('user_not_found', 'This user is not found on our database records');

    const { email, extras, signupMethod, joinedOn, encryptionKey, emailVerified, _id, profile, claims } = a,
        tokenData = {
            email,
            extras,
            signupMethod,
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
        }, projectName)
    ]);

    return { token: p[0], tokenData: { ...tokenData, expOn: TOKEN_EXPIRY() } };
}

export const refreshToken = async (token, projectName) => {
    const { tokenID, email } = await verifyJWT(token, projectName),
        acct = await Promise.all([
            readDocument({ path: EnginePath.tokenStore(), find: { _id: tokenID } }, projectName),
            readDocument({ path: EnginePath.userAcct(), find: { email } }, projectName)
        ]);

    if (!acct[0]) throw simplifyError('token_not_found', 'This token was not found in our records');
    if (!acct[1]) throw simplifyError('user_not_found', 'This user is not found on our database records');

    const { extras, signupMethod, joinedOn, encryptionKey, _id, claims, emailVerified, profile } = acct[1],
        tokenData = {
            email,
            extras,
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
        }, projectName)
    ]);

    return { token: p[0], tokenData: { ...tokenData, expOn: TOKEN_EXPIRY() } };
}

export const invalidateToken = (tokenID, projectName) => {
    return writeDocument({ path: EnginePath.tokenStore(), value: null, find: { _id: tokenID }, scope: 'delete' }, projectName);
}