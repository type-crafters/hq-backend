import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, Cookie, ExpiredTokenError, InvalidTokenError, Authenticator } from "@typecrafters/hq-lib";
import { type JSONResponse } from "@typecrafters/hq-types";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { BatchWriteCommand, DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";

const region = "us-east-1";
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

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { cookies } = event;

        if (!cookies) {
            logger.error("No token cookie to read. User is not authorized to use this endpoint.");
            return HttpResponse.builder()
                .status(HttpCode.Unauthorized)
                .json({
                    success: false,
                    message: "Unauthorized."
                } satisfies JSONResponse)
                .build();
        }

        let id;

        try {
            const cookielist = cookies.map(c => Cookie.from(c));
            const refreshToken = cookielist.find(c => c.name === "refreshToken");

            if (!refreshToken) {
                logger.error("No token cookie to read. User is not authorized to use this endpoint.");
                return unauthorized;
            }

            id = Authenticator.refresh(process.env).getSubNoExp(refreshToken.value);

            if (!id) {
                return unauthorized;
            }
        } catch (error) {
            if (error instanceof TypeError) {
                logger.error("One or more request cookies was malformed.");
                return unauthorized;
            } else if (error instanceof InvalidTokenError) {
                logger.error("Invalid token.");
                return unauthorized;
            }
            throw error;
        }

        const jtis = (await ddb.send(new QueryCommand({
            TableName: REFRESH_TOKEN_TABLE,
            IndexName: "sub-index",
            KeyConditionExpression: "#sub = :sub",
            ExpressionAttributeNames: { "#sub": "sub" },
            ExpressionAttributeValues: { ":sub": id },
            ProjectionExpression: "jti"
        }))).Items ?? [];

        let limit: number = 25;
        let offset: number = 0;

        do {
            await ddb.send(new BatchWriteCommand({
                RequestItems: {
                    REFRESH_TOKEN_TABLE: jtis.slice(offset, offset + limit).map(jti => ({
                        DeleteRequest: {
                            Key: jti
                        }
                    }))
                }
            }));
            offset += limit;
        } while (offset < jtis.length);

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .setCookies(
                Cookie.builder()
                    .name("accessToken")
                    .value("")
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("None")
                    .path("/")
                    .expires(new Date(0))
                    .build(),
                Cookie.builder()
                    .name("refreshToken")
                    .value("")
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("None")
                    .path("/")
                    .expires(new Date(0))
                    .build(),
            )
            .json({
                success: true,
                message: "User sessions revoked."
            } satisfies JSONResponse)
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