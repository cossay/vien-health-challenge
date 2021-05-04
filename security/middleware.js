const { parseRequestToken } = require('./service');
const { Token, User } = require('../database/models');

const userResolver = async function (secret) {
    const token = await Token.findOne({ secret }).exec();

    if (!token) {
        return null;
    }

    const user = await User.findOne({ _id: token.user_id }).exec();

    if (!user) {
        return null;
    }

    return { token, user };
};

function AuthMiddleware(req, res, next) {
    const secret = parseRequestToken(req.header("authorization"));

    if (!secret) {
        res.status(401).send({ message: 'Missing authorization token.' });
    } else {
        userResolver(secret).then((context) => {
            if (context) {
                req.user = context.user;
                req.token = context.token;
                next();
            } else {
                res.status(401).send({ message: 'Invalid authorization token.' });
            }
        }, (err) => {
            res.status(500).send({ message: err.message });
        });
    }
}

module.exports = { AuthMiddleware };