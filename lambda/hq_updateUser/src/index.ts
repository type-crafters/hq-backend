import assert from "assert";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, Cookie, Authenticator, ExpiredTokenError, InvalidTokenError } from "@typecrafters/hq-lib";
import type { UpdateUserRequest } from "./interface/UpdateUserRequest.js";
import { UserStatus } from "./enum/UserStatus.js";
import { ColorScheme } from "./enum/ColorScheme.js";
import { ConditionalCheckFailedException, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";

const AWS_REGION = "us-east-1";
const USER_TABLE = process.env.USER_TABLE;

assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }))

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body, cookies, pathParameters: params } = event;

        if (!cookies) {
            logger.error("No token cookie to read. User is not authorized to use this endpoint.");
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
            if (!permissions.includes("update:user")) {
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

        if (!params || !Object.keys(params).length) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("Missing or empty required path parameters.")
                .build()
        }

        const { id } = params;

        if (!id) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("Missing or empty required path parameters.")
                .build();
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
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("Malformed request body.")
                .build();
        }

        const {
            firstName,
            lastName,
            email,
            status,
            preferredTheme,
            profilePictureUrl
        }: UpdateUserRequest = data;

        if (
            (firstName && typeof firstName !== "string")
            ||
            (lastName && typeof lastName !== "string")
            ||
            (email && typeof email !== "string")
            ||
            (status && !(Object.values(UserStatus) as string[]).includes(status))
            ||
            (preferredTheme && !(Object.values(ColorScheme) as string[]).includes(preferredTheme))
            ||
            (profilePictureUrl && typeof profilePictureUrl !== "string")
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .text("Missing or malformed required fields.")
                .build();
        }

        const Item = Object.fromEntries(Object.entries({
            firstName,
            lastName,
            email,
            status,
            preferredTheme,
            profilePictureUrl
        }).filter(([_, v]) => !!v)) as Record<string, string>;

        let UpdateExpression: string = "";
        const expr: string[] = [];
        const ExpressionAttributeNames: Record<string, string> = {};
        const ExpressionAttributeValues: Record<string, string> = {};

        Object.entries(Item).forEach(([name, value]) => {
            expr.push(`#${name} = :${name}`);
            ExpressionAttributeNames[`#${name}`] = name;
            ExpressionAttributeValues[`:${name}`] = value;
        });

        if (expr.length) {
            UpdateExpression = `SET ${expr.join(", ")}`
            try {
                const result = await ddb.send(new UpdateCommand({
                    TableName: USER_TABLE,
                    Key: { id },
                    UpdateExpression,
                    ExpressionAttributeNames,
                    ExpressionAttributeValues,
                    ReturnValues: "ALL_NEW",
                    ConditionExpression: "attribute_exists(id)"
                }));
                return HttpResponse.builder()
                    .status(HttpCode.OK)
                    .json(result.Attributes!)
                    .build();
            } catch (error) {
                if (error instanceof ConditionalCheckFailedException) {
                    return HttpResponse.builder()
                        .status(HttpCode.NotFound)
                        .text("User not found.")
                        .build();
                }
                throw error;
            }
        }

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .text("No attributes updated.")
            .build();

    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .text("Internal server error.")
            .build();
    }
};

export { handler };