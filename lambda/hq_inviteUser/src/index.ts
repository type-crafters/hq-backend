import assert, { AssertionError } from "assert";
import path from "path";
import { createHash, randomBytes, randomUUID } from "crypto";
import { readFileSync } from "fs";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { InviteUserRequest } from "./interface/InviteUserRequest.js";
import { EJS, HttpResponse, HttpCode, Mailer, LoggerFactory } from "@typecrafters/hq-lib";
import { UserInviteItem } from "./interface/UserInviteItem.js";
import { UserStatus } from "./enum/UserStatus.js";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";

const AWS_REGION = "us-east-1";

const PAGE_URL = process.env.PAGE_URL;
const VERIFICATION_TOKEN_TABLE = process.env.VERIFICATION_TOKEN_TABLE;
const USER_TABLE = process.env.USER_TABLE;

assert(PAGE_URL, "Missing required environment variable 'PAGE_URL'.");
assert(VERIFICATION_TOKEN_TABLE, "Missing required environment variable 'VERIFICATION_TOKEN_TABLE'.")
assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'.")

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }))

const handler = async (event: APIGatewayProxyEventV2) => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        let body: InviteUserRequest;
        try {
            assert(event.body);
            body = JSON.parse(event.body);
            assert(body);
        } catch (error) {
            logger.error(error);
            let message: string = "An error occurred while parsing the request body.";
            if (error instanceof AssertionError) {
                message = "Missing request body."
            } else if (error instanceof SyntaxError) {
                message = "Malformed request body."
            }
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message })
                .parse();
        }

        const { firstName, lastName, email, permissions } = body;
        
        logger.debug("Asserting validity of fields...");
        try {
            assert(typeof firstName === "string" && firstName); 
            assert(typeof lastName === "string" && lastName);
            assert(typeof email === "string" && email);
            assert(permissions instanceof Array);
            logger.info("Assertion succeeded.")
        } catch (error) {
            logger.error(error);
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Missing or incorrect fields." })
                .parse();
        }

        logger.info("Checking email existence...");
        const queryResult = await ddb.send(new QueryCommand({
            TableName: USER_TABLE,
            IndexName: "email-index",
            KeyConditionExpression: "#email = :email",
            ExpressionAttributeNames: {
                "#email": "email"
            },
            ExpressionAttributeValues: {
                ":email": email
            },
            Select: "COUNT"
        }));

        if (queryResult.Count) {
            logger.error("Email already exists.")
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "A user with this email already exists." })
                .parse();
        }

        logger.info("Email does not exist. User can be invited.");


        const token: string = randomBytes(32).toString("base64url");
        const url = new URL(PAGE_URL);
        url.pathname = "/users/verify";
        url.searchParams.set("token", token);

        const template: string = readFileSync(
            path.join(import.meta.dirname, "template", "verify-email.ejs"),
            { encoding: "utf-8" }
        );

        const html: string = EJS.render(template).using({ firstName, url });

        logger.info("Sending verification email...");
        const mailer = new Mailer(process.env);
        await mailer.sendHTMLEmail(email, html, "Please verify your email address.");
        logger.info("Verification email sent.");

        logger.info("Hashing token...");
        const tokenHash: string = createHash("sha256")
            .update(token)
            .digest("base64url");

        logger.info("Token hashed.");

        const tokenItem = {
            hash: tokenHash,
            permissions,
            expires: Date.now() + 86_400 * 1_000
        }

        logger.info("Storing token in database...");
        await ddb.send(new PutCommand({
            TableName: VERIFICATION_TOKEN_TABLE,
            Item: tokenItem
        }));
        logger.info("Token stored.");

        logger.info("Storing partial user in database...");
        const userItem = {
            id: randomUUID(),
            firstName,
            lastName,
            email,
            status: UserStatus.Unverified
        } satisfies UserInviteItem;

        await ddb.send(new PutCommand({
            TableName: USER_TABLE,
            Item: userItem
        }));
        logger.info("Partial user stored.");

        return new HttpResponse().status(HttpCode.OK)
            .json({ message: "User invited." })
            .parse();

    } catch (error) {
        logger.error(error);
        return new HttpResponse().status(HttpCode.InternalServerError)
            .json({ message: "Internal server error." })
            .parse();
    }
};

export { handler };