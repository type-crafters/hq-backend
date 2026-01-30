import assert from "assert";
import path from "path";
import { createHash, randomBytes } from "crypto";
import { readFileSync } from "fs";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { InviteUserRequest } from "./interface/InviteUserRequest.js";
import { EJS, HttpResponse, HttpCode, Mailer } from "@typecrafters/hq-lib";

const API_URL = process.env.API_URL;

assert(API_URL, "Missing required environment variable 'API_URL'");

const handler = async (event: APIGatewayProxyEventV2) => {
    try {
        // assert event.body is not empty
        if (!event.body) {
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Missing request body." })
                .parse();
        }
 
        // parse event.body
        const { firstName, lastName, email }: InviteUserRequest = JSON.parse(event.body);

        // assert parsed body attribtues are not empty
        if (!firstName || !lastName || !email) {
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Missing required fields." })
                .parse();
        }

        // TODO Verify that a user with above email doesn't already exist


        // Create unique token for email verification
        const token: string = randomBytes(32).toString("base64url");
        const url = new URL(API_URL);
        url.pathname = "/users/verify";
        url.searchParams.set("token", token);

        // Store token hash in token table
        const tokenHash: string = createHash("sha256")
            .update(token)
            .digest("base64url");

        // TODO implement database access logic

        // Render EJS template for verification email
        const template: string = readFileSync(
            path.join(import.meta.dirname, "template", "verify-email.ejs"), 
            { encoding: "utf-8" }
        );

        const html: string = EJS.render(template).using({ firstName, url });

        // Send verification email 
        const mailer = new Mailer(process.env);
        await mailer.sendHTMLEmail(email, html, "Please verify your email address.");

        return new HttpResponse().status(HttpCode.OK)
            .json({  message: "User invited." })
            .parse();

    } catch (error) {
        return new HttpResponse().status(HttpCode.InternalServerError)
            .json({ message: "Internal server error." })
            .parse();
    }
};

export default handler;