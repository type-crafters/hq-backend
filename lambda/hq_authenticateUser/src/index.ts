import assert, { AssertionError } from "assert";
import { createHash, randomUUID } from "crypto";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { Cookie, HttpCode, HttpResponse, LoggerFactory } from "@typecrafters/hq-lib";
import type { UserLoginRequest } from "./interface/UserLoginRequest.js";
import type { VerifiableUser } from "./interface/VerifiableUser.js";
import type { AccessTokenClaims } from "./interface/AccessTokenClaims.js";
import { RefreshTokenClaims } from "./interface/RefreshTokenClaims.js";

const AWS_REGION = "us-east-1";
const ISS = "typecrafters.org";
const ACCESS_TTL = 15 * 60 * 1000; // 15m
const REFRESH_TTL = 7 * 86_400 * 1000; // 7d

const USER_TABLE = process.env.USER_TABLE;
const REFRESH_TOKEN_TABLE = process.env.REFRESH_TOKEN_TABLE;
const ACCESS_SECRET = process.env.ACCESS_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'.");
assert(REFRESH_TOKEN_TABLE, "Missing required environment variable 'REFRESH_TOKEN_TABLE'.");
assert(ACCESS_SECRET, "Missing required environment variable 'ACCESS_SECRET'.");
assert(REFRESH_SECRET, "Missing required environment variable 'REFRESH_SECRET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

const handler = async (event: APIGatewayProxyEventV2) => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        let body: UserLoginRequest;
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

        const { email, password, rememberMe } = body;

        try {
            assert(typeof email === "string" && email);
            assert(typeof password === "string" && password);
            assert(typeof rememberMe === "boolean");
        } catch (error) {
            logger.error(error);
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Missing or incorrect fields." })
                .parse();
        }

        const result = await ddb.send(new QueryCommand({
            TableName: USER_TABLE,
            IndexName: "email-index",
            KeyConditionExpression: "#email = :email",
            ExpressionAttributeNames: {
                "#email": "email"
            },
            ExpressionAttributeValues: {
                ":email": email
            },
            Limit: 1
        }));

        logger.info("Verifying result item existence...");
        try {
            assert(result.Items?.length && Object.keys(result.Items[0]).length);
            logger.info("Result exists and is not empty.")
        } catch {
            logger.error("User with specified information not found.");
            return new HttpResponse().status(HttpCode.Unauthorized)
                .json({ message: "Authentication failed." })
                .parse();
        }

        const user = result.Items[0] as VerifiableUser;

        logger.info("Verifying passwords...");
        if (!(await bcrypt.compare(password, user.password))) {
            logger.error("Passwords do not match.");
            return new HttpResponse().status(HttpCode.Unauthorized)
            .json({ message: "Authentication failed." })
            .parse();
        }

        logger.info("Password verification succeeded");

        const accessClaims: AccessTokenClaims = {
            iss: ISS,
            jti: randomUUID(),
            iat: Math.round(Date.now() / 1000),
            exp: Math.round((Date.now() + ACCESS_TTL) / 1000),
            typ: "access",
            sub: user.id,
            eml: user.email,
            rol: Array.from(user.roles)
        };

        const refreshClaims: RefreshTokenClaims = {
            iss: ISS,
            jti: randomUUID(),
            iat: Math.round(Date.now() / 1000),
            exp: Math.round((Date.now() + REFRESH_TTL) / 1000),
            typ: "refresh",
            sub: user.id,
        };

        await ddb.send(new PutCommand({
            TableName: REFRESH_TOKEN_TABLE,
            Item: { 
                ...refreshClaims, 
                jti: createHash("sha256").update(refreshClaims.jti).digest("base64url") 
            }
        }));

        const accessToken = jwt.sign(accessClaims, ACCESS_SECRET);
        const refreshToken = jwt.sign(refreshClaims, REFRESH_SECRET);

        return new HttpResponse().status(HttpCode.OK)
            .setCookie(Cookie.builder()
                .name("accessToken")
                .value(accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .expires(new Date(accessClaims.exp * 1000))
                .build()
            )
            .setCookie(Cookie.builder()
                .name("refreshToken")
                .value(refreshToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .expires(new Date(refreshClaims.exp * 1000))
                .build()
            )
            .json({ 
                message: "User authenticated.",
                roles: Array.from(user.roles)
            })
            .parse();

    } catch (error) {
        logger.error(error);
        return new HttpResponse().status(HttpCode.InternalServerError)
            .json({ message: "Internal server error." })
            .parse();
    }
};

export { handler };