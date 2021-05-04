'use strict';

const express = require('express');
const bodyParser = require('body-parser')
const mongoose = require('mongoose');
const { Auth, User, Token } = require('./database/models');
const { generateToken } = require('./security/service');
const { AuthMiddleware } = require('./security/middleware');

const app = express();
app.use(bodyParser.json());
const port = 5050;

mongoose.connect('mongodb://localhost/vienhealthchallenge', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});

const conn = mongoose.connection;

conn.once('open', () => console.log('DB connected'));

app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        let token;

        await conn.transaction(async (session) => {
            const profile = new User({ name, email });
            await profile.save({ session });

            const auth = new Auth({ password, user_id: profile._id });
            await auth.save({ session });

            token = generateToken();

            const authToken = new Token({ user_id: profile._id, secret: token });
            await authToken.save({ session });
        });

        res.status(201).send({ token });
    } catch (e) {
        if (e instanceof mongoose.Error.ValidationError) {
            res.status(400).send({ message: e.message });
        } else {
            res.status(500).send({ message: e.message });
        }
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).exec();

    const message = 'Invalid email or password';

    if (!user) {
        res.status(401).send({ message });
    } else {
        const auth = await Auth.findOne({ user_id: user._id }).exec();
        const matched = await auth.matchPasswords(password);

        if (matched) {
            const token = generateToken();
            const authToken = new Token({ user_id: user._id, secret: token });
            await authToken.save();

            res.send({ token });
        } else {
            res.status(401).send({ message });
        }
    }
});

//app.delete('/api/logout', async (req, res) => { });
app.get('/api/logout', [AuthMiddleware], async (req, res) => {
    try {
        await Token.findOneAndDelete({ _id: req.token._id }).exec();
        res.send({ message: 'Logout successful.' });
    } catch (error) {
        res.status(500).send({ message: error.message });
    }
});

app.get('/api/profile', [AuthMiddleware], async (req, res) => {
    const profile = req.user;
    res.send(profile);
});

app.listen(port, () => {
    console.log(`API running @ ${port}`);
});

module.exports = app;
