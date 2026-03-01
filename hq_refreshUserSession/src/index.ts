import { randomUUID } from "crypto";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { type AccessTokenClaims, type JSONResponse, type RefreshTokenClaims } from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, Cookie, ExpiredTokenError, InvalidTokenError, Authenticator } from "@typecrafters/hq-lib";
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand } from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException, DynamoDBClient } from "@aws-sdk/client-dynamodb";

const region = "us-east-1";
const ACCESS_EXP = 15 * 60 * 1_000; // 15m 
const unauthorized = HttpResponse.builder()
    .status(HttpCode.Unauthorized)
    .json({
        success: false,
        message: "Unauthorized."
    } satisfies JSONResponse)
    .build();

const REFRESH_TOKEN_TABLE = process.env.REFRESH_TOKEN_TABLE;
if (!REFRESH_TOKEN_TABLE) throw new Error("Missing required environment variable 'REFRESH_TOKEN_TABLE'.");
if (!process.env.REFRESH_SECRET) throw new Error("Missing required environment variable 'REFRESH_SECRET'.");
if (!process.env.ACCESS_SECRET) throw new Error("Missing required environment variable 'ACCESS_SECRET'.");
if (!process.env.JTI_SECRET) throw new Error("Missing required environment variable 'JTI_SECRET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { cookies } = event;
        if (!cookies) return unauthorized;

        let accessCookie;
        let refreshCookie;

        try {
            const cookielist = cookies.map(c => Cookie.from(c));
            accessCookie = cookielist.find(c => c.name === "accessToken");
            refreshCookie = cookielist.find(c => c.name === "refreshToken");

            if (!accessCookie || !refreshCookie) return unauthorized;
        } catch (error) {
            if (error instanceof TypeError) return unauthorized;
            throw error;
        }

        const authAccess = Authenticator.access(process.env);
        const authRefresh = Authenticator.refresh(process.env);

        const { sub: accessSub, eml: email, prm: permissions } = authAccess.getClaimsNoExp(accessCookie.value);
        const { jti: jtiHash, exp, sub: refreshSub } = authRefresh.hashJTI(authRefresh.getClaims(refreshCookie.value));

        if (!jtiHash) return unauthorized;
        if (accessSub !== refreshSub) return unauthorized;

        const sub = accessSub;

        const now = Date.now();
        if (now > (exp * 1_000)) return unauthorized;

        try {
            await ddb.send(new DeleteCommand({
                TableName: REFRESH_TOKEN_TABLE,
                Key: { jti: jtiHash },
                ConditionExpression: "attribute_exists(jti)"
            }));

        } catch (error) {
            if (error instanceof ConditionalCheckFailedException) {
                return unauthorized;
            }
            throw error;
        }

        const accessClaims = authAccess.issue({
            jti: randomUUID(),
            iat: Math.round(now / 1000),
            exp: Math.round((now + ACCESS_EXP) / 1000),
            sub,
            eml: email,
            prm: permissions
        } satisfies AccessTokenClaims);

        const refreshClaims = authRefresh.issue({
            jti: randomUUID(),
            iat: Math.round(now / 1000),
            exp,
            sub
        } satisfies RefreshTokenClaims);

        await ddb.send(new PutCommand({
            TableName: REFRESH_TOKEN_TABLE,
            Item: authRefresh.hashJTI(refreshClaims)
        }));

        const accessToken = authAccess.sign(accessClaims);
        const refreshToken = authRefresh.sign(refreshClaims);

        return HttpResponse
            .builder()
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
            ).json({
                success: true,
                message: "Token verified. Session extended."
            } satisfies JSONResponse)
            .build();

    } catch (error) {
        logger.error(error);
        if (error instanceof ExpiredTokenError) return unauthorized;
        if (error instanceof InvalidTokenError) return unauthorized;
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .json({
                success: false,
                message: "A server-side error occurred."
            } satisfies JSONResponse)
            .build()
    }
};

export { handler };