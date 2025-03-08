import { OAuth2Client } from "google-auth-library";
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, EnginePath, ERRORS } from "../../helpers/values";
import { queryDocument, writeDocument } from "../database";
import { signinCustom, signupCustom } from "./email_auth";
import { Validator } from "guard-object";

export const validateGoogleAuthConfig = (config) => {
    if (!Validator.OBJECT(config)) throw 'expected a raw object for googleAuthConfig';

    const { clientID } = config;
    if (typeof clientID !== 'string' || !clientID.trim()) throw 'clientID in googleAuthConfig is invalid';
};

export const doGoogleSignin = async ({ googleAuthConfig, token, projectName, mergeAuthAccount }, req, interceptNewAuth, metax) => {
    if (!googleAuthConfig) throw ERRORS.GOOGLE_AUTH_DISABLED;

    const { clientID } = googleAuthConfig;
    const client = new OAuth2Client(clientID);
    const userInfo = (await client.verifyIdToken({ idToken: token, audience: clientID })).getPayload();

    if (!userInfo?.email || !userInfo?.email_verified) throw ERRORS.GOOGLE_AUTH_FAILED;
    if (Date.now() > userInfo.exp * 1000) throw ERRORS.GOOGLE_TOKEN_EXPIRED;

    const { email_verified, name, given_name, family_name, picture, sub } = userInfo;
    const email = userInfo.email.toLowerCase().trim();
    const namex = name || given_name || family_name;

    const [subAccount, emailAccount] = await Promise.all([
        { [AUTH_PROVIDER_ID.GOOGLE]: sub },
        ...mergeAuthAccount ? [{ email }] : []
    ].map(q =>
        queryDocument(
            {
                path: EnginePath.userAcct,
                find: q
            },
            projectName,
            ADMIN_DB_NAME,
            ADMIN_DB_URL
        )
    ));

    const userRecord = subAccount[0] || (emailAccount || []).find(v => v.password);
    if (userRecord) {
        if (!userRecord[AUTH_PROVIDER_ID.GOOGLE]) {
            userRecord[AUTH_PROVIDER_ID.GOOGLE] = sub;
            await writeDocument({
                path: EnginePath.userAcct,
                find: { _id: userRecord._id },
                value: { $set: { [AUTH_PROVIDER_ID.GOOGLE]: sub } },
                scope: 'updateOne'
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        }

        return {
            ...(await signinCustom(email, undefined, AUTH_PROVIDER_ID.GOOGLE, projectName, userRecord)),
            isNewUser: false
        };
    }

    const aBuild = {
        email,
        name: namex,
        photo: picture,
        request: req,
        metadata: metax,
        method: AUTH_PROVIDER_ID.GOOGLE,
        token,
        providerData: userInfo
    };
    const {
        metadata = metax || {},
        profile,
        uid: d_uid
    } = (await interceptNewAuth?.(aBuild)) || {};

    return {
        ...(await signupCustom(
            email,
            undefined,
            AUTH_PROVIDER_ID.GOOGLE,
            {
                name: namex,
                photo: picture,
                email
            },
            projectName,
            {
                verified: email_verified,
                sub: sub,
                metadata: {
                    ...Validator.OBJECT(metadata) ? metadata : {}
                },
                profile: {
                    ...Validator.OBJECT(profile) ? profile : {}
                },
                d_uid
            }
        )),
        isNewUser: true
    };
};