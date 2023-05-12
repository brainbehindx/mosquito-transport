import { sign, verify } from "jsonwebtoken"
import { TOKEN_EXPIRY } from "../../helpers/values";
import { Scoped } from "../../helpers/variables"

export const verifyJWT = async (token, projectName) => new Promise((resolve, reject) => {
    verify(token, Scoped.AuthHashToken[projectName], undefined, (err, r) => {
        if (err) reject(err);
        else resolve(r);
    });
});

export const signJWT = (payload, projectName) => new Promise((reject, resolve) => {
    sign(
        { ...payload },
        Scoped.AuthHashToken[projectName],
        {
            exp: TOKEN_EXPIRY() / 1000, // 1 hour
            aud: projectName,
            iss: 'mosquitodb',
            sub: 'auth_token'
        },
        (err, token) => {
            if (err) reject(err);
            else resolve(token);
        }
    );
});