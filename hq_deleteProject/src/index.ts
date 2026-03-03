import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { type JSONResponse } from "@typecrafters/hq-types";
import {
    HttpResponse,
    HttpCode,
    LoggerFactory,
    type ResponseObject,
    ExpiredTokenError,
    InvalidTokenError,
    Cookie,
    Authenticator,
} from "@typecrafters/hq-lib";
import {
    ConditionalCheckFailedException,
    DynamoDBClient,
} from "@aws-sdk/client-dynamodb";
import { DeleteCommand, DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

const region = "us-east-1";
const PROJECT_TABLE = process.env.PROJECT_TABLE;
const unauthorized = HttpResponse.builder()
    .status(HttpCode.Unauthorized)
    .json({
        success: false,
        message: "Unauthorized.",
    } satisfies JSONResponse)
    .build();

if (!PROJECT_TABLE)
    throw new Error("Missing required environment variable 'PROJECT_TABLE'.");
if (!process.env.ACCESS_SECRET)
    throw new Error("Missing required environment variable 'ACCESS_SECRET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (
    event: APIGatewayProxyEventV2,
): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { pathParameters, cookies } = event;

        if (!cookies) return unauthorized;

        try {
            const accessToken = cookies
                .map((c) => Cookie.from(c))
                .find((c) => c.name === "accessToken");

            if (!accessToken) return unauthorized;

            const permissions = Authenticator.access(
                process.env,
            ).getPermissions(accessToken.value);

            if (!permissions.includes("delete:project")) {
                return HttpResponse.builder()
                    .status(HttpCode.Forbidden)
                    .json({
                        success: false,
                        message: "User not authorized to perform this action.",
                    } satisfies JSONResponse)
                    .build();
            }
        } catch (error) {
            if (error instanceof SyntaxError) return unauthorized;
            if (error instanceof ExpiredTokenError) return unauthorized;
            if (error instanceof InvalidTokenError) return unauthorized;
            throw error;
        }

        if (!pathParameters || !pathParameters.id) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty required path parameters.",
                } satisfies JSONResponse)
                .build();
        }

        const { id } = pathParameters;

        try {
            await ddb.send(
                new DeleteCommand({
                    TableName: PROJECT_TABLE,
                    Key: { id },
                    ConditionExpression: "attribute_exists(id)",
                }),
            );
        } catch (error) {
            if (error instanceof ConditionalCheckFailedException) {
                return HttpResponse.builder()
                    .status(HttpCode.NotFound)
                    .json({
                        success: false,
                        message: "Project not found.",
                    } satisfies JSONResponse)
                    .build();
            }
            throw error;
        }

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .json({
                success: true,
                message: "Project successfully deleted.",
            } satisfies JSONResponse)
            .build();
    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .json({
                success: false,
                message: "A server-side error occurred.",
            } satisfies JSONResponse)
            .build();
    }
};

export { handler };
