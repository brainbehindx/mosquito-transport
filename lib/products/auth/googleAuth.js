import { OAuth2Client } from "google-auth-library";
import EnginePath from "../../helpers/EnginePath";
import { IS_RAW_OBJECT, simplifyError } from "../../helpers/utils"
import { ADMIN_DB_NAME, ADMIN_DB_URL } from "../../helpers/values";
import { queryDocument, readDocument } from "../database";
import { signinCustom, signupCustom } from "./customAuth";

export const validateGoogleAuthConfig = (config) => {
    if (!IS_RAW_OBJECT(config)) throw 'expected a raw object for googleAuthConfig';

    const { clientID } = config;
    if (typeof clientID !== 'string' || !clientID.trim()) throw 'clientID in googleAuthConfig is invalid';
}

export const doGoogleSignin = async ({ googleAuthConfig, token, projectName, mergeAuthAccount }) => {
    if (!googleAuthConfig)
        throw simplifyError(
            'google_auth_disabled',
            'You haven\'t enable google auth yet, provide the "googleAuthConfig" in MosquitoDbServer() constructor to enable this feature'
        );

    const { clientID } = googleAuthConfig,
        client = new OAuth2Client(clientID),
        userInfo = (await client.verifyIdToken({ idToken: token, audience: clientID })).getPayload();

    if (!userInfo) throw simplifyError('google_auth_failed', 'This user couldn\'t be authenticate');
    if (Date.now() > userInfo.exp * 1000) throw simplifyError('google_auth_token_expired', 'The google token provided has already expired');

    const { email_verified, name, given_name, family_name, picture, sub, locale } = userInfo,
        email = userInfo.email.toLowerCase().trim();

    let userRecord = await queryDocument({
        path: EnginePath.userAcct(),
        find: mergeAuthAccount ? { $or: [{ 'google_sub': sub }, { email }] } : { 'google_sub': sub }
    },
        projectName,
        ADMIN_DB_NAME,
        ADMIN_DB_URL
    );

    if (!userRecord.length || userRecord.length === 1) {
        userRecord = userRecord[1];
    } else {
        const bb = [...userRecord];
        userRecord = userRecord.filter(v => v.google_sub === sub)[0];
        if (!userRecord) userRecord = bb[0];
    }

    if (userRecord && (!userRecord.profile?.enforceAcct || userRecord.google_sub === sub))
        return signinCustom(email, undefined, 'google', projectName, userRecord);

    return signupCustom(email, undefined, 'google', {
        name: name || given_name || family_name,
        photo: picture
    }, projectName, { verified: email_verified, sub: sub });
}