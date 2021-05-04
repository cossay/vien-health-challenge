const sha256 = require('sha256');
const uuid = require('uuid');
const randomstring = require("randomstring");

function generateToken() {
    return sha256(`${uuid.v1()}${randomstring.generate()}`);
}

function parseRequestToken(rawToken) {
    return String(rawToken || '').split(' ').pop();
}

module.exports = { generateToken, parseRequestToken };