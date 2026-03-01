import type { APIGatewayProxyEventV2 } from "aws-lambda";
import {
    UserStatus,
    type AccessTokenClaims,
    type AuthenticateUserRequest,
    type JSONResponse,
    type RefreshTokenClaims,
    type UserItem
} from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, Authenticator, Cookie } from "@typecrafters/hq-lib";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { BatchWriteCommand, DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import bcrypt from "bcrypt";
import { randomUUID } from "crypto";

const region = "us-east-1";
const ACCESS_EXP = 15 * 60 * 1_000; // 15m
const REFRESH_EXP_SHORT = 86_400 * 1_000; // 1d
const REFRESH_EXP_LONG = 60 * 86_400 * 1_000; // 60d

const USER_TABLE = process.env.USER_TABLE;
const REFRESH_TOKEN_TABLE = process.env.REFRESH_TOKEN_TABLE;

if (!USER_TABLE) throw new Error("Missing required environment variable 'USER_TABLE'.");
if (!REFRESH_TOKEN_TABLE) throw new Error("Missing required environment variable 'REFRESH_TOKEN_TABLE'.");

if (!process.env.JTI_SECRET) throw new Error("Missing required environment variable 'JTI_SECRET'.")
if (!process.env.ACCESS_SECRET) throw new Error("Missing required environment variable 'ACCESS_SECRET'.");
if (!process.env.REFRESH_SECRET) throw new Error("Missing required environment variable 'REFRESH_SECRET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const authenticationFailed = HttpResponse.builder()
    .status(HttpCode.Unauthorized)
    .json({
        success: false,
        message: "Authentication failed"
    } satisfies JSONResponse)
    .build();

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body } = event;
        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty request body."
                } satisfies JSONResponse)
                .build();
        }

        let data: AuthenticateUserRequest;

        try {
            data = JSON.parse(body);
        } catch (error) {
            if (error instanceof SyntaxError) {
                return HttpResponse.builder()
                    .status(HttpCode.BadRequest)
                    .json({
                        success: false,
                        message: "Malformed request body."
                    } satisfies JSONResponse)
                    .build();
            }
            throw error;
        }

        const { email, password, rememberMe } = data;

        if (
            !email || typeof email !== "string"
            ||
            !password || typeof password !== "string"
            ||
            typeof rememberMe !== "boolean"
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or invalid required fields."
                } satisfies JSONResponse)
                .build();
        }

        const result = await ddb.send(new QueryCommand({
            TableName: USER_TABLE,
            IndexName: "email-index",
            KeyConditionExpression: "#email = :email",
            ExpressionAttributeNames: { "#email": "email" },
            ExpressionAttributeValues: { ":email": email.trim().toLowerCase() },
            Limit: 1
        }));

        if (!result.Items || !result.Items.length) {
            return authenticationFailed;
        }

        const user = result.Items[0] as UserItem;

        if (user.status !== UserStatus.Active) {
            return authenticationFailed;
        }

        if (!(await bcrypt.compare(password, user.password))) {
            return authenticationFailed;
        }

        const pAccess = Authenticator.access(process.env);
        const pRefresh = Authenticator.refresh(process.env);

        const permissionList = Array.from(user.permissions ?? []);
        const now = Date.now();

        const accessClaims = pAccess.issue({
            jti: randomUUID(),
            iat: Math.round(now / 1000),
            exp: Math.round((now + ACCESS_EXP) / 1000),
            sub: user.id,
            eml: user.email,
            prm: permissionList
        } satisfies AccessTokenClaims);
        
        const refreshClaims = pRefresh.issue({
            jti: randomUUID(),
            iat: Math.round(now / 1000),
            exp: Math.round((now + (rememberMe ? REFRESH_EXP_LONG : REFRESH_EXP_SHORT)) / 1000),
            sub: user.id
        } satisfies RefreshTokenClaims);

        const jtis = (await ddb.send(new QueryCommand({
            TableName: REFRESH_TOKEN_TABLE,
            IndexName: "sub-index",
            KeyConditionExpression: "#sub = :sub",
            ExpressionAttributeNames: { "#sub": "sub" },
            ExpressionAttributeValues: { ":sub": user.id },
            ProjectionExpression: "jti"
        }))).Items ?? [];

        let limit: number = 25;
        let offset: number = 0;

        do {
            await ddb.send(new BatchWriteCommand({
                RequestItems: {
                    REFRESH_TOKEN_TABLE: jtis.slice(offset, offset + limit).map(jti => ({
                        DeleteRequest: { 
                            Key: { jti }
                        }
                    }))
                }
            }));
            offset += limit;
        } while (offset < jtis.length);

        await ddb.send(new PutCommand({
            TableName: REFRESH_TOKEN_TABLE,
            Item: pRefresh.hashJTI(refreshClaims)
        }));

        const accessToken = pAccess.sign(accessClaims);
        const refreshToken = pRefresh.sign(refreshClaims);

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
            .json({
                success: true,
                message: "Authentication succeeded.",
                item: permissionList
            } satisfies JSONResponse<string[]>)
            .build();
    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .json({
                success: false,
                message: "A server-side error occurred."
            } satisfies JSONResponse)
            .build();
    }
};

export { handler };