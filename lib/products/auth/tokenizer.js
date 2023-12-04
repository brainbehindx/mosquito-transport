import pkg from 'jsonwebtoken';
import EnginePath from '../../helpers/EnginePath';
import { simplifyError } from '../../helpers/utils';
import { ADMIN_DB_NAME, ADMIN_DB_URL, TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables"
import { readDocument } from '../database';

const { sign, verify } = pkg;

export const verifyJWT = async (token, projectName) => new Promise((resolve, reject) => {
    verify(token, Scoped.AuthHashToken[projectName], { ignoreExpiration: true }, (err, r) => {
        if (err) reject(err);
        else resolve(r);
    });
});

export const signJWT = (payload, projectName) => new Promise((resolve, reject) => {
    const options = {
        exp: TOKEN_EXPIRY(projectName) / 1000,
        aud: projectName,
        iss: 'mosquitodb',
        sub: 'auth_token'
    };

    sign(
        { ...options, ...payload },
        Scoped.AuthHashToken[projectName], undefined,
        (err, token) => {
            if (err) reject(err);
            else resolve(token);
        }
    );
});

export const validateJWT = async (token, projectName) => {
    try {
        const auth = await verifyJWT(token, projectName),
            expiry = (auth.exp || 0) * 1000;

        if (auth && (
            Date.now() > expiry ||
            !(await readDocument({ path: EnginePath.tokenStore, find: { _id: auth.tokenID } }, projectName, ADMIN_DB_NAME, ADMIN_DB_URL))
        )) {
            if (Date.now() > expiry) throw simplifyError('token_expired', 'The provided token has already expired');
            throw simplifyError('token_not_found', 'This token was not found in our records');
        }
        return auth;
    } catch (e) {
        if (!e.simpleError) throw simplifyError('invalid_auth_token', `${e}`);
        throw e;
    }
}