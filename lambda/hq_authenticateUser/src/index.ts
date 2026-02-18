import assert from "assert";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import bcrypt from "bcrypt";
import { Authenticator, Cookie, LoggerFactory, HttpResponse, HttpCode, type ResponseObject } from "@typecrafters/hq-lib";
import type { AuthenticateUserRequest } from "./interface/AuthenticateUserRequest.js";
import type { User } from "./interface/User.js";
import type { AccessTokenClaims } from "./interface/AccessTokenClaims.js";
import type { RefreshTokenClaims } from "./interface/RefreshTokenClaims.js";
import { randomUUID } from "crypto";

const AWS_REGION = "us-east-1";
const ACCESS_TTL = 15 * 60 * 1000;
const REFRESH_TTL = 7 * 86_400 * 1000;

const USER_TABLE = process.env.USER_TABLE;
const REFRESH_TOKEN_TABLE = process.env.REFRESH_TOKEN_TABLE;

assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'.");
assert(REFRESH_TOKEN_TABLE, "Missing required environment variable 'REFRESH_TOKEN_TABLE'.");

assert(process.env.JTI_SECRET, "Missing required environment variable 'JTI_SECRET'.")
assert(process.env.ACCESS_SECRET, "Missing required environment variable 'ACCESS_SECRET'.");
assert(process.env.REFRESH_SECRET, "Missing required environment variable 'REFRESH_SECRET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body } = event;
        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("Missing request body.")
                .build();
        }
        try {
            const { email, password, rememberMe }: AuthenticateUserRequest = JSON.parse(body);

            if (!email || typeof email !== "string") throw new TypeError();
            if (!password || typeof password !== "string") throw new TypeError();
            if (typeof rememberMe !== "boolean") throw new TypeError();

            const result = await ddb.send(new QueryCommand({
                TableName: USER_TABLE,
                IndexName: "email-index",
                KeyConditionExpression: "#email = :email",
                ExpressionAttributeNames: { "#email": "email" },
                ExpressionAttributeValues: { ":email": email },
                Limit: 1
            }));

            if (!result.Items || !result.Items.length || !Object.keys(result.Items[0]).length) {
                return HttpResponse.builder()
                    .status(HttpCode.Unauthorized)
                    .text("Authentication failed")
                    .build();
            }

            const user = result.Items[0] as User;

            if (!(await bcrypt.compare(password, user.password!))) {
                return HttpResponse.builder()
                    .status(HttpCode.Unauthorized)
                    .text("Authentication failed")
                    .build();
            }

            const permissionlist = Array.from(user.permissions ?? []);

            const access = Authenticator.access(process.env);
            const refresh = Authenticator.refresh(process.env);

            const accessClaims = access.issue({
                jti: randomUUID(),
                iat: Math.round(Date.now() / 1000),
                exp: Math.round((Date.now() + ACCESS_TTL) / 1000),
                sub: user.id,
                eml: user.email,
                prm: permissionlist
            } satisfies AccessTokenClaims);

            const refreshClaims = refresh.issue({
                jti: randomUUID(),
                iat: Math.round(Date.now() / 1000),
                exp: Math.round((Date.now() + REFRESH_TTL) / 1000),
                sub: user.id,
            } satisfies RefreshTokenClaims);

            await ddb.send(new PutCommand({
                TableName: REFRESH_TOKEN_TABLE,
                Item: refresh.hashJTI(refreshClaims)
            }));

            const accessToken = access.sign(accessClaims);
            const refreshToken = refresh.sign(refreshClaims);

            return HttpResponse.builder()
                .status(HttpCode.OK)
                .setCookies(
                    Cookie.builder()
                        .name("accessToken")
                        .value(accessToken)
                        .httpOnly(true)
                        .secure(true)
                        .sameSite("None")
                        .path("/")
                        .expires(new Date(accessClaims.exp * 1000))
                        .build(),
                    Cookie.builder()
                        .name("refreshToken")
                        .value(refreshToken)
                        .httpOnly(true)
                        .secure(true)
                        .sameSite("None")
                        .path("/")
                        .expires(new Date(refreshClaims.exp * 1000))
                        .build()
                )
                .json({ message: "Authentication succeeded", permissions: permissionlist })
                .build();

        } catch (error) {
            if (error instanceof TypeError || error instanceof SyntaxError) {
                return HttpResponse.builder()
                    .status(HttpCode.BadRequest)
                    .text("Missing or malformed required fields.")
                    .build();
            }
            throw error;
        }
    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .text("Internal server error")
            .build();
    }
};
 
export { handler };