import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { HttpResponse, HttpCode, LoggerFactory } from "@typecrafters/hq-lib";
import assert from "assert";
import { DynamoDBDocumentClient, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { UpdateUserRequest } from "./interface/UpdateUserRequest.js";

const AWS_REGION = "us-east-1";
const USER_TABLE = process.env.USER_TABLE;

assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

const handler = async (event: APIGatewayProxyEventV2) => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body, pathParameters } = event;

        if (!body || !pathParameters) {
            logger.error("Request body or path parameters not provided.");
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Missing required request data." })
                .parse();
        }

        const id = pathParameters.id;

        if (!id) {
            logger.error("Missing id in event.pathParameters");
            return new HttpResponse().status(HttpCode.BadGateway)
                .json({ message: "Missing required path parameters." })
                .parse();
        }

        const {
            firstName,
            lastName,
            email,
            status,
            preferredTheme,
            profilePictureUrl
        }: UpdateUserRequest = JSON.parse(body);

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
                return new HttpResponse().status(HttpCode.OK)
                    .json(result.Attributes)
                    .parse();
            } catch (error) {
                if (error instanceof ConditionalCheckFailedException) {
                    return new HttpResponse().status(HttpCode.NotFound)
                        .json({ message: "User not found." })
                        .parse();
                }
            }
        }
    } catch (error) {
        logger.error(error);
        return new HttpResponse().status(HttpCode.InternalServerError)
            .json({ message: "Internal server error." })
            .parse();
    }
};

export { handler };