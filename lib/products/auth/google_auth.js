import { OAuth2Client } from "google-auth-library";
import { simplifyError } from "simplify-error";
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, EnginePath } from "../../helpers/values";
import { queryDocument, writeDocument } from "../database";
import { signinCustom, signupCustom } from "./email_auth";
import { Validator } from "guard-object";

export const validateGoogleAuthConfig = (config) => {
    if (!Validator.OBJECT(config)) throw 'expected a raw object for googleAuthConfig';

    const { clientID } = config;
    if (typeof clientID !== 'string' || !clientID.trim()) throw 'clientID in googleAuthConfig is invalid';
}

export const doGoogleSignin = async ({ googleAuthConfig, token, projectName, mergeAuthAccount }, req, sneakSignupAuth, metax) => {
    if (!googleAuthConfig)
        throw simplifyError(
            'google_auth_disabled',
            'You haven\'t enable google auth yet, provide the "googleAuthConfig" in MosquitoTransportServer() constructor to enable this feature'
        );

    const { clientID } = googleAuthConfig,
        client = new OAuth2Client(clientID),
        userInfo = (await client.verifyIdToken({ idToken: token, audience: clientID })).getPayload();

    if (!userInfo?.email || !userInfo?.email_verified)
        throw simplifyError('google_auth_failed', 'This user couldn\'t be authenticate');
    if (Date.now() > userInfo.exp * 1000)
        throw simplifyError('google_auth_token_expired', 'The google token provided has already expired');

    const { email_verified, name, given_name, family_name, picture, sub, locale } = userInfo,
        email = userInfo.email.toLowerCase().trim(),
        namex = name || given_name || family_name;

    let userRecord = await queryDocument({
        path: EnginePath.userAcct,
        find: mergeAuthAccount ? { $or: [{ 'google_sub': sub }, { email }] } : { 'google_sub': sub }
    },
        projectName,
        ADMIN_DB_NAME,
        ADMIN_DB_URL
    );

    const bb = [...userRecord];
    userRecord = userRecord.filter(v => v.google_sub === sub)[0];
    if (!userRecord) userRecord = bb[0];

    if (userRecord) {
        if (!userRecord.google_sub) {
            userRecord.google_sub = sub;
            await writeDocument({
                path: EnginePath.userAcct,
                find: { _id: userRecord._id },
                value: { $set: { google_sub: sub } },
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
    } = (await sneakSignupAuth?.(aBuild)) || {};

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
}