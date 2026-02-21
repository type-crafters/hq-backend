import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { DeleteObjectsCommand, ListObjectsV2Command, S3Client, type ListObjectsV2CommandOutput } from "@aws-sdk/client-s3";
import { ConditionalCheckFailedException, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DeleteCommand, DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { HttpResponse, HttpCode, type ResponseObject, LoggerFactory, Cookie, Authenticator, ExpiredTokenError, InvalidTokenError } from "@typecrafters/hq-lib";
import path from "path";
import assert, { AssertionError } from "assert";

const AWS_REGION = "us-east-1";

const BUCKET = process.env.BUCKET;
const USER_TABLE = process.env.USER_TABLE;
const REFRESH_TOKEN_TABLE = process.env.REFRESH_TOKEN_TABLE;
const ACCESS_SECRET = process.env.ACCESS_SECRET;

assert(ACCESS_SECRET, "Missing required environment variable 'ACCESS_SECRET'.");
assert(BUCKET, "Missing required environment variable 'BUCKET'.");
assert(REFRESH_TOKEN_TABLE, "Missing required environment variable 'REFRESH_TOKEN_TABLE'.");
assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'.");


const s3 = new S3Client({ region: AWS_REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { cookies, pathParameters: params } = event;

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
            if (!permissions.includes("delete:user")) {
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

        const tokenResult = await ddb.send(new QueryCommand({
            TableName: REFRESH_TOKEN_TABLE,
            IndexName: "sub-index",
            KeyConditionExpression: "#sub = :sub",
            ExpressionAttributeNames: { "#sub": "sub" },
            ExpressionAttributeValues: { ":sub": id }
        }));

        if (tokenResult) {
            const tokens = tokenResult.Items;
            if (tokens && tokens.length) {
                await Promise.all(tokens.map(async token => await ddb.send(new DeleteCommand({
                    TableName: REFRESH_TOKEN_TABLE,
                    Key: { jti: token.jti }
                }))));
            }
        }

        let continuationToken: string | undefined = undefined;
        let mediaResult: ListObjectsV2CommandOutput;

        do {
            mediaResult = await s3.send(new ListObjectsV2Command({
                Bucket: BUCKET,
                Prefix: path.posix.join("img", `pfp-${id}`),
                ContinuationToken: continuationToken
            }));

            if (mediaResult) {
                const media = mediaResult.Contents;

                if (media && media.length) {
                    await s3.send(new DeleteObjectsCommand({
                        Bucket: BUCKET,
                        Delete: { Objects: media.map(m => ({ Key: m.Key! })) }
                    }));
                }
            }

            continuationToken = mediaResult.NextContinuationToken;

        } while (continuationToken);

        try {
            await ddb.send(new DeleteCommand({
                TableName: USER_TABLE,
                Key: { id },
                ConditionExpression: "attribute_exists(id)"
            }));

            return HttpResponse.builder()
                .status(HttpCode.NoContent)
                .build()

        } catch (error) {
            if (error instanceof ConditionalCheckFailedException) {
                return HttpResponse.builder()
                    .status(HttpCode.NotFound)
                    .text("User not found.")
                    .build();
            }
            throw error;
        }

    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .text("Internal server error.")
            .build();
    }
};

export { handler };