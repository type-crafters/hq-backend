import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { type JSONResponse, type MemberItem } from "@typecrafters/hq-types";
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
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import {
    ConditionalCheckFailedException,
    DynamoDBClient,
} from "@aws-sdk/client-dynamodb";

const region = "us-east-1";
const MEMBER_TABLE = process.env.MEMBER_TABLE;
const unauthorized = HttpResponse.builder()
    .status(HttpCode.Unauthorized)
    .json({
        success: false,
        message: "Unauthorized.",
    } satisfies JSONResponse)
    .build();

if (!MEMBER_TABLE)
    throw new Error("Missing required environment variable 'MEMBER_TABLE'.");
if (!process.env.ACCESS_SECRET)
    throw new Error("Missing required environment variable 'ACCESS_SECRET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (
    event: APIGatewayProxyEventV2,
): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { pathParameters, body, cookies } = event;

        if (!cookies) return unauthorized;

        try {
            const accessToken = cookies
                .map((c) => Cookie.from(c))
                .find((c) => c.name === "accessToken");

            if (!accessToken) return unauthorized;

            const permissions = Authenticator.access(
                process.env,
            ).getPermissions(accessToken.value);

            if (!permissions.includes("update:member")) {
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

        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty request body.",
                } satisfies JSONResponse)
                .build();
        }

        let data: Record<string, any>;

        try {
            data = JSON.parse(body);
        } catch (error) {
            if (error instanceof SyntaxError) {
                return HttpResponse.builder()
                    .status(HttpCode.BadRequest)
                    .json({
                        success: false,
                        message: "Malformed request body.",
                    } satisfies JSONResponse)
                    .build();
            }
            throw error;
        }

        if (
            (data.firstName && typeof data.firstName !== "string") ||
            (data.lastName && typeof data.lastName !== "string") ||
            (data.role && typeof data.role !== "string") ||
            (data.bio && typeof data.bio !== "string") ||
            (data.email && typeof data.email !== "string") ||
            (data.profilePictureUrl &&
                typeof data.profilePictureUrl !== "string") ||
            (data.since && typeof data.since !== "number")
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or invalid required fields.",
                } satisfies JSONResponse)
                .build();
        }

        let updateExpression = "";
        const expr: string[] = [];
        const expressionAttributeNames: Record<string, string> = {};
        const expressionAttributeValues: Record<string, any> = {};

        Object.entries(data).forEach(([name, value]) => {
            if (value == null) return;
            expr.push(`#${name} = :${name}`);
            expressionAttributeNames[`#${name}`] = name;
            expressionAttributeValues[`:${name}`] = value;
        });

        if (!expr.length) {
            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({
                    success: true,
                    message: "No fields updated.",
                } satisfies JSONResponse)
                .build();
        }

        expr.push("#lastUpdatedAt = :timestamp");
        expressionAttributeNames["#lastUpdatedAt"] = "lastUpdatedAt";
        expressionAttributeValues[":timestamp"] = Date.now();
        updateExpression = `SET ${expr.join(", ")}`;

        try {
            const result = await ddb.send(
                new UpdateCommand({
                    TableName: MEMBER_TABLE,
                    Key: { id },
                    UpdateExpression: updateExpression,
                    ExpressionAttributeNames: expressionAttributeNames,
                    ExpressionAttributeValues: expressionAttributeValues,
                    ReturnValues: "ALL_NEW",
                    ConditionExpression: "attribute_exists(id)",
                }),
            );

            const item = result.Attributes as MemberItem;

            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({
                    success: true,
                    message: "Team member successfully updated.",
                    item,
                } satisfies JSONResponse<MemberItem>)
                .build();
        } catch (error) {
            if (error instanceof ConditionalCheckFailedException) {
                return HttpResponse.builder()
                    .status(HttpCode.NotFound)
                    .json({
                        success: false,
                        message: "Team member not found.",
                    } satisfies JSONResponse)
                    .build();
            }
            throw error;
        }
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
