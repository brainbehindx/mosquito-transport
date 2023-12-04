import { OAuth2Client } from "google-auth-library";
import EnginePath from "../../helpers/EnginePath";
import { IS_RAW_OBJECT, simplifyError } from "../../helpers/utils"
import { ADMIN_DB_NAME, ADMIN_DB_URL } from "../../helpers/values";
import { queryDocument, writeDocument } from "../database";
import { signinCustom, signupCustom } from "./customAuth";

export const validateGoogleAuthConfig = (config) => {
    if (!IS_RAW_OBJECT(config)) throw 'expected a raw object for googleAuthConfig';

    const { clientID } = config;
    if (typeof clientID !== 'string' || !clientID.trim()) throw 'clientID in googleAuthConfig is invalid';
}

export const doGoogleSignin = async ({ googleAuthConfig, token, projectName, mergeAuthAccount }, req, sneakSignupAuth, metax) => {
    if (!googleAuthConfig)
        throw simplifyError(
            'google_auth_disabled',
            'You haven\'t enable google auth yet, provide the "googleAuthConfig" in MosquitoDbServer() constructor to enable this feature'
        );

    const { clientID } = googleAuthConfig,
        client = new OAuth2Client(clientID),
        userInfo = (await client.verifyIdToken({ idToken: token, audience: clientID })).getPayload();

    if (!userInfo?.email || !userInfo?.email_verified) throw simplifyError('google_auth_failed', 'This user couldn\'t be authenticate');
    if (Date.now() > userInfo.exp * 1000) throw simplifyError('google_auth_token_expired', 'The google token provided has already expired');

    const { email_verified, name, given_name, family_name, picture, sub, locale } = userInfo,
        email = userInfo.email.toLowerCase().trim();

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
            ...(await signinCustom(email, undefined, 'google', projectName, userRecord)),
            isNewUser: false
        };
    }

    const aBuild = { email, name, request: req, metadata: metax, method: 'google', token },
        { metadata = metax || {}, profile, uid: d_uid } = sneakSignupAuth?.(aBuild) || {};

    return {
        ...(await signupCustom(email, undefined, 'google', {
            name: name || given_name || family_name,
            photo: picture
        }, projectName, {
            verified: email_verified,
            sub: sub,
            metadata: {
                ...(IS_RAW_OBJECT(metadata) ? metadata : {})
            },
            profile: {
                ...(IS_RAW_OBJECT(profile) ? profile : {})
            },
            d_uid
        })),
        isNewUser: true
    };
}