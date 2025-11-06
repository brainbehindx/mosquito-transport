import jwt from "jsonwebtoken";
import jwksClient from "jwks-rsa";
import { ERRORS } from "../../helpers/values";

const rsaClientMap = {};

export const verifyPublicKey = ({ endpoint, issuers }) =>
    async (identityToken, audience) => {
        // Decode JWT header
        const decoded = jwt.decode(identityToken, { complete: true });
        if (!decoded) throw ERRORS.AUTH_INVALID_TOKEN;

        // Get public key
        const rsaClient = rsaClientMap[endpoint] || (
            rsaClientMap[endpoint] = jwksClient({
                jwksUri: endpoint,
                cacheMaxEntries: 7,
                cacheMaxAge: 24 * 60 * 60 * 1000
            })
        );

        const key = await rsaClient.getSigningKey(decoded.header.kid);
        const publicKey = key.getPublicKey();

        // Verify JWT signature
        const verified = jwt.verify(identityToken, publicKey, {
            algorithms: ["RS256"]
        });

        // Validate claims
        if (!issuers.some(v => v === verified.iss)) throw ERRORS.UNEXPECTED_TOKEN_ISSUER;
        if (!audience.some(v => v === verified.aud)) throw ERRORS.UNEXPECTED_TOKEN_AUDIENCE;
        if (Date.now() > verified.exp * 1000) throw ERRORS.AUTH_TOKEN_EXPIRED;

        return verified;
    };