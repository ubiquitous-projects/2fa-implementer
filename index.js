#!/usr/bin/env node

`use strict`;

const colors = require(`colors`);
const express = require(`express`);
const { JsonDB } = require(`node-json-db`);
const { Config } = require(`node-json-db/dist/lib/JsonDBConfig`);
const speakeasy = require(`speakeasy`);
const uuid = require(`uuid`);

const app = express();
const database = new JsonDB(new Config(`./backend/database`, true, false, `/`));

app.get(`/`, (request, response) => {
    response.status(200).json({ response: `Welcome to 2fa-implementer.` });

    return;
});

app.post(`/api/registration`, (request, response) => {
    const user_id = uuid.v4();

    try {
        const user_path = `/user/${user_id}`;

        const user_key = speakeasy.generateSecret();

        database.push(user_path, {
            user_id: user_id,
            user_key: user_key,
            key_verified: false,
        });

        response.status(200).json({
            user_id: user_id,
            user_key: user_key.base32,
            response: `Security key successfully generated.`,
        });

        return;
    } catch (err) {
        console.error(err.message.brightRed);

        response
            .status(500)
            .json({ response: `Error generating your security key.` });

        return;
    }
});

app.post(`/api/key/validation`, (request, response) => {
    const { user_id, user_token } = request.body;

    try {
        const user_path = `/user/${user_id}`;

        const user_data = database.getData(user_path);

        const user_key = user_data.user_key.base32;

        const validation_status = speakeasy.totp.verify({
            user_key,
            encoding: `base32`,
            user_token,
            window: 1,
        });

        if (validation_status) {
            response.status(200).json({
                validated: true,
                response: `Security key successfully validated.`,
            });

            return;
        }

        response.status(200).json({
            validated: false,
            response: `Security key NOT validated.`,
        });

        return;
    } catch (err) {
        console.error(err.message.brightRed);

        response
            .status(500)
            .json({ response: `Error validating your security key.` });

        return;
    }
});

app.post(`/api/key/verification`, (request, response) => {
    const { user_id, user_token } = request.body;
    try {
        const user_path = `/user/${user_id}`;

        const user_data = database.getData(user_path);

        const user_key = user_data.user_key.base32;

        const verification_status = speakeasy.totp.verify({
            user_key,
            encoding: `base32`,
            user_token,
        });

        if (verification_status) {
            database.push(user_path, { user_id: user_id, key_verified: true });

            response.status(200).json({
                verified: true,
                response: `Security key successfully verified.`,
            });

            return;
        }

        response
            .status(200)
            .json({ verified: false, response: `Security key NOT verified.` });

        return;
    } catch (err) {
        console.error(err.message.brightRed);

        response
            .status(500)
            .json({ response: `Error verifying your security key.` });

        return;
    }
});

const port = process.env.PORT || 5000;

app.listen(port, () => {
    console.log(
        `2fa-implementer listening on port: `.brightWhite,
        `${port}`.brightGreen
    );

    return;
});
