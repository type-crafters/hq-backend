import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ProjectStatus, type JSONResponse } from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject } from "@typecrafters/hq-lib";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";

const region = "us-east-1";
const PROJECT_TABLE = process.env.PROJECT_TABLE;

assert(PROJECT_TABLE, "Missing required environment variable 'PROJECT_TABLE'");

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

        const { projectName, thumbnailUrl, description, content, status, tags } = data;

        if (
            projectName === undefined &&
            thumbnailUrl === undefined &&
            description === undefined &&
            content === undefined &&
            status === undefined &&
            tags === undefined
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "At least one field must be provided for update."
                } satisfies JSONResponse)
                .build();
        }

        const { projectName, thumbnailUrl, description, content, status, tags, href }: UpdateProjectRequest = data;

        if (
            typeof projectName !== "string" || !projectName
            ||
            typeof thumbnailUrl !== "string" || !thumbnailUrl
            ||
            typeof description !== "string" || !description
            ||
            (content && typeof content !== "string")
            ||
            typeof status !== "string" || !Object.values(ProjectStatus).includes(status)
            ||
            !Array.isArray(tags) || tags.some(t => typeof t !== "string")
            || 
            typeof tags !== "string" || !tags
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or invalid required fields."
                } satisfies JSONResponse)
                .build();
        }

        // Build update expression and attribute values
        const updateParts: string[] = [];
        const attributeValues: Record<string, any> = {};
        const fieldConfigs: Record<string, { needsAttributeName?: boolean }> = {
            projectName: {},
            thumbnailUrl: {},
            description: {},
            content: {},
            status: { needsAttributeName: true },
            tags: {}
        };

        let expressionIndex = 0;
        const fieldData = { projectName, thumbnailUrl, description, content, status, tags };

        for (const [field, value] of Object.entries(fieldData)) {
            if (value !== undefined) {
                const config = fieldConfigs[field];
                const placeholder = `:val${expressionIndex}`;
                const fieldName = config?.needsAttributeName ? `#${field}` : field;
                
                updateParts.push(`${fieldName} = ${placeholder}`);
                attributeValues[placeholder] = field === "tags" ? new Set(value as string[]) : value;
                expressionIndex++;
            }
        }

        updateParts.push(`lastUpdatedAt = :timestamp`);
        attributeValues[`:timestamp`] = Date.now();

        const updateExpression = `SET ${updateParts.join(", ")}`;
        const expressionAttributeNames = status !== undefined ? { "#status": "status" } : undefined;

        const result = await ddb.send(new UpdateCommand({
            TableName: PROJECT_TABLE,
            Key: { id },
            UpdateExpression: updateExpression,
            ExpressionAttributeValues: attributeValues,
            ExpressionAttributeNames: expressionAttributeNames,
            ReturnValues: "ALL_NEW"
        }));

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .json({
                success: true,
                message: "Project successfully updated.",
                item: result.Attributes
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