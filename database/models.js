const { Schema, SchemaTypes, model } = require('mongoose');
const { v1 } = require('uuid');
const { isEmail } = require('class-validator');
const { hash, verify } = require('argon2');

const schemaOptions = { versionKey: false };

const AuthSchema = new Schema({
    _id: { type: SchemaTypes.String, default: v1 },
    user_id: {
        type: SchemaTypes.String,
        unique: true,
        required: [true, 'User Id required.']
    },
    password: {
        type: SchemaTypes.String,
        required: true
    }
}, schemaOptions);

AuthSchema.pre('save', async function () {
    if (this.isModified('password')) {
        this.password = await hash(this.password);
    }
});

AuthSchema.methods.matchPasswords = async function (password) {
    return await verify(this.password, password);
};

const UserSchema = new Schema({
    _id: { type: SchemaTypes.String, default: v1 },
    name: {
        type: SchemaTypes.String,
        required: [true, 'Name required.']
    },
    email: {
        type: SchemaTypes.String,
        unique: true,
        required: [true, 'Email address required.'],
        validate: {
            validator: (v) => {
                return isEmail(v, { require_tld: true });
            },
            message: 'Invalid email address.'
        }
    }
}, schemaOptions);

const TokenSchema = new Schema({
    _id: { type: SchemaTypes.String, default: v1 },
    user_id: {
        type: SchemaTypes.String,
        required: true
    },
    secret: {
        type: SchemaTypes.String,
        unique: true,
        required: true
    },
}, schemaOptions);

const Auth = model('Auth', AuthSchema);
const User = model('User', UserSchema);
const Token = model('Token', TokenSchema);

User.schema.path('email').validate(async (email) => {
    const profile = await User.findOne({ email }).exec();
    return !(profile instanceof User);
}, 'Provided email address is taken.');

module.exports = { Auth, Token, User };