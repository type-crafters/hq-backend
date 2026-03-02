import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ProjectStatus, type JSONResponse, type ProjectItem, type ProjectResponse, type UpdateProjectRequest } from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject } from "@typecrafters/hq-lib";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException, DynamoDBClient } from "@aws-sdk/client-dynamodb";

const region = "us-east-1";
const PROJECT_TABLE = process.env.PROJECT_TABLE;

if (!PROJECT_TABLE) throw new Error("Missing required environment variable 'PROJECT_TABLE'");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { pathParameters, body } = event;

        if (!pathParameters || !pathParameters.id) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty required path parameters."
                } satisfies JSONResponse)
                .build();
        }

        const { id } = pathParameters;

        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty request body."
                } satisfies JSONResponse)
                .build();
        }

        let data;

        try {
            data = JSON.parse(body) as UpdateProjectRequest;
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

        if (
            (data.projectName && typeof data.projectName !== "string")
            ||
            (data.thumbnailUrl && typeof data.thumbnailUrl !== "string")
            ||
            (data.description && typeof data.description !== "string")
            ||
            (data.content && typeof data.content !== "string")
            ||
            (data.href && typeof data.href !== "string")
            ||
            (data.status && !Object.values(ProjectStatus).includes(data.status))
            ||
            (data.tags && !(Array.isArray(data.tags) && data.tags.every(t => typeof t === "string")))
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or invalid required fields."
                } satisfies JSONResponse)
                .build();
        }

        let UpdateExpression: string = "";
        const expr: string[] = [];
        const ExpressionAttributeNames: Record<string, string> = {};
        const ExpressionAttributeValues: Record<string, any> = {};

        Object.entries(data).forEach(([name, value]) => {
            if (value == null) return;
            expr.push(`#${name} = :${name}`);
            ExpressionAttributeNames[`#${name}`] = name;
            ExpressionAttributeValues[`:${name}`] = value;
        });

        if (expr.length) {
            expr.push("#lastUpdatedAt = :timestamp");
            ExpressionAttributeNames["#lastUpdatedAt"] = "lastUpdatedAt";
            ExpressionAttributeValues[":timestamp"] = Date.now();
            UpdateExpression = `SET ${expr.join(", ")}`;

            try {
                const result = await ddb.send(new UpdateCommand({
                    TableName: PROJECT_TABLE,
                    Key: { id },
                    UpdateExpression,
                    ExpressionAttributeNames,
                    ExpressionAttributeValues,
                    ReturnValues: "ALL_NEW",
                    ConditionExpression: "attribute_exists(id)",
                }));

                const attributes = result.Attributes as ProjectItem;

                const item = {
                    ...attributes,
                    tags: Array.from(attributes.tags ?? [])
                } satisfies ProjectResponse;

                return HttpResponse.builder()
                    .status(HttpCode.OK)
                    .json({
                        success: true,
                        message: "Project successfully updated.",
                        item: item
                    } satisfies JSONResponse<ProjectResponse>)
                    .build();

            } catch (error) {
                if (error instanceof ConditionalCheckFailedException) {
                    return HttpResponse.builder()
                        .status(HttpCode.NotFound)
                        .json({
                            success: false,
                            message: "Project not found."
                        })
                        .build();
                }
                throw error;
            }
        } else {
            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({
                    success: true,
                    message: "No fields updated.",
                } satisfies JSONResponse)
                .build();
        }
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