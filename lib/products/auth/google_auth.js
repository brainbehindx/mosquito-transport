import { timeoutFetch } from "../../helpers/utils";
import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, EnginePath, ERRORS } from "../../helpers/values";
import { queryDocument, writeDocument } from "../database";
import { signinCustom, signupCustom } from "./email_auth";
import { Validator } from "guard-object";
import { verifyPublicKey } from "./rsa_verifier";

export const validateGoogleAuthConfig = (config) => {
    if (!Validator.OBJECT(config)) throw 'expected a raw object for googleAuthConfig';

    const { clientID, clientSecret } = config;
    if (!Validator.NON_EMPTY_STRING(clientID)) throw 'clientID in googleAuthConfig is invalid';
    if (clientSecret !== undefined && !Validator.NON_EMPTY_STRING(clientSecret))
        throw 'clientSecret in googleAuthConfig is invalid';
};

const isIdToken = token => token.split('.').length === 3;

const tokenVerifier = verifyPublicKey({
    endpoint: 'https://www.googleapis.com/oauth2/v3/certs',
    issuers: ['https://accounts.google.com', 'accounts.google.com']
});

export const doGoogleSignin = async ({ googleAuthConfig, token, projectName, mergeAuthAccount }, req, interceptNewAuth, metax) => {
    if (!googleAuthConfig) throw ERRORS.GOOGLE_AUTH_DISABLED;

    const { clientID, clientSecret } = googleAuthConfig;

    let userInfo;

    if (isIdToken(token)) {
        userInfo = await tokenVerifier(token, clientID);
    } else {
        if (!clientSecret) throw 'clientSecret in googleAuthConfig is required when using authorization code to signin';
        token = await timeoutFetch('https://oauth2.googleapis.com/token', {
            body: JSON.stringify({
                code: token,
                'client_id': clientID,
                'client_secret': clientSecret,
                'redirect_uri': 'postmessage',
                'grant_type': 'authorization_code'
            }),
            method: 'POST'
        }).then(async r => (await r.json()).id_token);
        userInfo = JSON.parse(token.split('.')[1]);
    }

    if (!userInfo?.email || !userInfo?.email_verified) throw ERRORS.GOOGLE_AUTH_FAILED;
    if (Date.now() > userInfo.exp * 1000) throw ERRORS.GOOGLE_TOKEN_EXPIRED;

    const { name, given_name, family_name, picture, sub } = userInfo;
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

    const userRecord = subAccount[0] || emailAccount?.[0];
    if (userRecord) {
        if (userRecord[AUTH_PROVIDER_ID.GOOGLE] !== sub) {
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