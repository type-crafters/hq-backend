import assert from "assert";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import {
    LoggerFactory,
    HttpResponse,
    HttpCode,
    Authenticator,
    ExpiredTokenError,
    InvalidTokenError,
    Cookie,
    EJS,
    Mailer,
    type ResponseObject
} from "@typecrafters/hq-lib";
import type { InviteUserRequest } from "./interface/InviteUserRequest.js";
import { createHash, randomBytes, randomUUID } from "crypto";
import { readFileSync } from "fs";
import path from "path";
import { UserStatus } from "./enum/UserStatus.js";

const AWS_REGION = "us-east-1";

const PAGE_URL = process.env.PAGE_URL;
const VERIFICATION_TOKEN_TABLE = process.env.VERIFICATION_TOKEN_TABLE;
const USER_TABLE = process.env.USER_TABLE;
const SMTP_SERVICE = process.env.SMTP_SERVICE;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM;

assert(PAGE_URL, "Missing required environment variable 'PAGE_URL'.");
assert(VERIFICATION_TOKEN_TABLE, "Missing required environment variable 'VERIFICATION_TOKEN_TABLE'.")
assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'.")

assert(SMTP_SERVICE, "Missing required environment variable 'SMTP_SERVICE'.");
assert(SMTP_USER, "Missing required environment variable 'SMTP_USER'.");
assert(SMTP_PASS, "Missing required environment variable 'SMTP_PASS'.");
assert(SMTP_FROM, "Missing required environment variable 'SMTP_FROM'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }))

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body, cookies } = event;

        if (!cookies) {
            logger.error("No cookies sent in request. User is not authorized to use this endpoint.");
            return HttpResponse.builder()
                .status(HttpCode.Unauthorized)
                .text("Unauthorized.")
                .build();
        }

        try {
            const cookielist = cookies.map(c => Cookie.from(c));
            const accessToken = cookielist.find(c => c.name === "accessToken");

            if (!accessToken) {
                logger.error("No token cookie to read. User is not authorized to use this endpoint.");
                return HttpResponse.builder()
                    .status(HttpCode.Unauthorized)
                    .text("Unauthorized.")
                    .build();
            }

            const permissions = Authenticator.access(process.env).getPermissions(accessToken.value);

            if (!permissions.includes("create:user")) {
                return HttpResponse.builder()
                    .status(HttpCode.Forbidden)
                    .text("User not authorized to perform this action.")
                    .build();
            }
        } catch (error) {
            const response = HttpResponse.builder()
                .status(HttpCode.Unauthorized)
                .text("Unauthorized.")
                .build();
            if (error instanceof TypeError) {
                logger.error("One or more request cookies was malformed.");
                return response;
            } else if (error instanceof ExpiredTokenError) {
                logger.error("Token expired.");
                return response;
            } else if (error instanceof InvalidTokenError) {
                logger.error("Invalid token.");
                return response;
            }
            throw error;
        }

        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("Missing request body.")
                .build();
        }

        let data;

        try {
            data = JSON.parse(body);
        } catch (error) {
            if (error instanceof SyntaxError) {
                return HttpResponse.builder()
                    .status(HttpCode.BadRequest)
                    .text("Malformed request body.")
                    .build();
            }
        }

        const { firstName, lastName, email, permissions }: InviteUserRequest = data;
        if (
            !firstName || typeof firstName !== "string"
            ||
            !lastName || typeof lastName !== "string"
            ||
            !email || typeof email !== "string"
            ||
            !(permissions instanceof Array)
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("Invalid or malformed body fields.")
                .build();
        }

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
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("User with this email already exists.")
                .build();
        }

        const token: string = randomBytes(32).toString("base64url");
        const url = new URL("/users/verify", PAGE_URL);
        url.searchParams.set("token", token);

        const template: string = readFileSync(
            path.join(import.meta.dirname, "template", "verify-email.ejs"),
            { encoding: "utf-8" }
        );

        const html: string = EJS.render(template).using({ firstName, url });
        const mailer = new Mailer(process.env);
        await mailer.sendHTMLEmail(email, html, "Please verify your email address.");

        const tokenHash: string = createHash("sha256")
            .update(token)
            .digest("base64url");

        await ddb.send(new PutCommand({
            TableName: VERIFICATION_TOKEN_TABLE,
            Item: {
                hash: tokenHash,
                permissions,
                expires: Date.now() + (86_400 * 1_000)
            }
        }));

        await ddb.send(new PutCommand({
            TableName: USER_TABLE,
            Item: {
                id: randomUUID(),
                firstName,
                lastName,
                email,
                status: UserStatus.Unverified
            }
        }));
        return HttpResponse.builder()
            .status(HttpCode.OK)
            .text("User invited.")
            .build();
    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .text("Internal server error.")
            .build();
    }
}

export { handler };