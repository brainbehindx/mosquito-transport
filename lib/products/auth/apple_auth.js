import { ADMIN_DB_NAME, ADMIN_DB_URL, AUTH_PROVIDER_ID, EnginePath, ERRORS } from "../../helpers/values";
import { queryDocument, writeDocument } from "../database";
import { signinCustom, signupCustom } from "./email_auth";
import { Validator } from "guard-object";
import { verifyPublicKey } from "./rsa_verifier";

export const validateAppleAuthConfig = (config) => {
    if (!Validator.OBJECT(config)) throw 'expected a raw object for appleAuthConfig';

    const { serviceID } = config;
    if (!Validator.NON_EMPTY_STRING(serviceID)) throw 'serviceID in appleAuthConfig is invalid';
};

const tokenVerifier = verifyPublicKey({
    endpoint: 'https://appleid.apple.com/auth/keys',
    issuers: ['https://appleid.apple.com']
});

export const doAppleSignin = async ({ appleAuthConfig, token, projectName, mergeAuthAccount }, req, interceptNewAuth, metax) => {
    if (!appleAuthConfig) throw ERRORS.APPLE_AUTH_DISABLED;
    const { serviceID } = appleAuthConfig;

    const userInfo = await tokenVerifier(token, serviceID.split(',').map(v => v.trim()));

    if (!userInfo?.email || userInfo?.email_verified !== true) throw ERRORS.APPLE_AUTH_FAILED;

    const { sub } = userInfo;
    const email = userInfo.email.toLowerCase().trim();

    const [subAccount, emailAccount] = await Promise.all([
        { [AUTH_PROVIDER_ID.APPLE]: sub },
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
        if (userRecord[AUTH_PROVIDER_ID.APPLE] !== sub) {
            userRecord[AUTH_PROVIDER_ID.APPLE] = sub;
            await writeDocument({
                path: EnginePath.userAcct,
                find: { _id: userRecord._id },
                value: { $set: { [AUTH_PROVIDER_ID.APPLE]: sub } },
                scope: 'updateOne'
            }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL)
        }

        return {
            ...(await signinCustom(email, undefined, AUTH_PROVIDER_ID.APPLE, projectName, userRecord)),
            isNewUser: false
        };
    }

    const aBuild = {
        email,
        request: req,
        metadata: metax,
        method: AUTH_PROVIDER_ID.APPLE,
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
            AUTH_PROVIDER_ID.APPLE,
            { email },
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