import bcrypt from "bcrypt";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { HttpCode, HttpResponse, LoggerFactory, type ResponseObject } from "@typecrafters/hq-lib";
import { UserStatus, type FinalizeUserRequest, type JSONResponse } from "@typecrafters/hq-types";
import { createHash } from "node:crypto";
import { DynamoDBDocumentClient, TransactWriteCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient, TransactionCanceledException } from "@aws-sdk/client-dynamodb";

const region = "us-east-1";
const USER_TABLE = process.env.USER_TABLE;
const VERIFICATION_TOKEN_TABLE = process.env.VERIFICATION_TOKEN_TABLE;

if (!USER_TABLE) throw new Error("Missing required environment variable 'USER_TABLE'.");
if (!VERIFICATION_TOKEN_TABLE) throw new Error("Missing required environment variable 'VERIFICATION_TOKEN_TABLE'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body, queryStringParameters: searchParams } = event;

        if (!searchParams) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty querystring."
                } satisfies JSONResponse)
                .build();
        }

        const { token, sub } = searchParams;

        if (!token) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty required query string parameters."
                } satisfies JSONResponse)
                .build();
        }

        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty request body."
                } satisfies JSONResponse)
                .build();
        }

        let data: FinalizeUserRequest;

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

        const { password, confirmPassword } = data;

        if (
            !password || typeof password !== "string"
            ||
            !confirmPassword || typeof confirmPassword !== "string"
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or invalid required fields."
                } satisfies JSONResponse)
                .build();
        }

        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,128}$/;

        if (!regex.test(password)) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Passwords must be between 8 and 128 characters long, and include at least one uppercase letter, one lowercase letter and one number."
                } satisfies JSONResponse)
                .build();
        }

        if (password !== confirmPassword) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Passwords do not match."
                } satisfies JSONResponse)
                .build();
        }

        const now = Date.now();

        const tokenHash = createHash("sha256")
            .update(token)
            .digest("hex");

        const passwordHash = await bcrypt.hash(password, 10);

        try {
            await ddb.send(new TransactWriteCommand({
                TransactItems: [
                    {
                        Update: {
                            TableName: USER_TABLE,
                            Key: { id: sub },
                            UpdateExpression: "SET #password = :password, #status = :status, #lastUpdatedAt = :lastUpdatedAt",
                            ExpressionAttributeNames: {
                                "#password": "password",
                                "#status": "status",
                                "#lastUpdatedAt": "lastUpdatedAt"
                            },
                            ExpressionAttributeValues: {
                                ":password": passwordHash,
                                ":status": UserStatus.Active,
                                ":lastUpdatedAt": now
                            },
                            ConditionExpression: "attribute_exists(id)"
                        },
                    },
                    {
                        Delete: {
                            TableName: VERIFICATION_TOKEN_TABLE,
                            Key: { token: tokenHash },
                            ConditionExpression: "attribute_exists(token) AND #sub = :sub AND #expiresAt > :now",
                            ExpressionAttributeNames: {
                                "#sub": "sub",
                                "#expiresAt": "expiresAt"
                            },
                            ExpressionAttributeValues: {
                                ":sub": sub,
                                ":now": (Math.floor(now/1000))
                            }
                        }
                    }
                ]
            }));
        } catch (error) {
            if (error instanceof TransactionCanceledException) {
                return HttpResponse.builder()
                    .status(HttpCode.NotFound)
                    .json({
                        success: false,
                        message: "The provided token was not found."
                    } satisfies JSONResponse)
                    .build();
            }
            throw error;
        }

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .json({
                success: true,
                message: "Account activated."
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