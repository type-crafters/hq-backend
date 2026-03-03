import { randomUUID } from "crypto";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { ProjectStatus, type CreateProjectRequest, type JSONResponse, type ProjectItem } from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, ExpiredTokenError, InvalidTokenError, Cookie, Authenticator } from "@typecrafters/hq-lib";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";

const region = "us-east-1";
const PROJECT_TABLE = process.env.PROJECT_TABLE;
const unauthorized = HttpResponse.builder()
    .status(HttpCode.Unauthorized)
    .json({
        success: false,
        message: "Unauthorized."
    } satisfies JSONResponse)
    .build();

if (!PROJECT_TABLE) throw new Error("Missing required environment variable 'PROJECT_TABLE'.");
if (!process.env.ACCESS_SECRET) throw new Error("Missing required environment variable 'ACCESS_SECRET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body, cookies } = event;

        if (!cookies) return unauthorized; 

        try {
            const accessToken = cookies
                .map(c => Cookie.from(c))
                .find(c => c.name === "accessToken");

            if (!accessToken) return unauthorized;

            const permissions = Authenticator.access(process.env).getPermissions(accessToken.value);

            if (!permissions.includes("create:project")) {
                return HttpResponse.builder()
                    .status(HttpCode.Forbidden)
                    .json({
                        success: false,
                        message: "User not authorized to perform this action."
                    } satisfies JSONResponse)
                    .build();
            }
        } catch (error) {
            if (error instanceof SyntaxError) return unauthorized;
            if (error instanceof ExpiredTokenError) return unauthorized;
            if (error instanceof InvalidTokenError) return unauthorized
            throw error;
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

        const { projectName, thumbnailUrl, description, content, status, tags, href }: CreateProjectRequest = data;

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
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or invalid required fields."
                } satisfies JSONResponse)
                .build();
        }

        const now = Date.now();

        await ddb.send(new PutCommand({
            TableName: PROJECT_TABLE,
            Item: {
                id: randomUUID(),
                projectName,
                thumbnailUrl,
                description,
                content,
                status,
                tags: new Set(tags),
                href,
                createdAt: now,
                lastUpdatedAt: now
            } satisfies ProjectItem
        }));

        return HttpResponse.builder()
            .status(HttpCode.Created)
            .json({
                success: true,
                message: "Project successfully created."
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