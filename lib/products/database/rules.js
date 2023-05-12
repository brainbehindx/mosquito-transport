

const rules = `const entry = (node = 'user%uid%') => ({
    'name': {
        read: () => true,
        write: () => true,
        validate: () => true,
        query: () => true
    }
});`;

export const authorizeRequest = async (req, type) => {

    return null;
    const { access_token, commands } = req.body,
        auth = verifyJWT();
}