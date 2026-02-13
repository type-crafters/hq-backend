import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { LoggerFactory, HttpResponse, HttpCode } from "@typecrafters/hq-lib";
import assert from "assert";
import { DeleteObjectsCommand, ListObjectsV2Command, type ListObjectsV2CommandOutput, S3Client } from "@aws-sdk/client-s3";
import { DeleteCommand, DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException, DynamoDBClient } from "@aws-sdk/client-dynamodb";
import path from "path";

const AWS_REGION = "us-east-1";

const BUCKET = process.env.BUCKET;
const REFRESH_TOKEN_TABLE = process.env.REFRESH_TOKEN_TABLE;
const USER_TABLE = process.env.USER_TABLE;

assert(BUCKET, "Missing required environment variable 'BUCKET'.");
assert(REFRESH_TOKEN_TABLE, "Missing required environment variable 'REFRESH_TOKEN_TABLE'.");
assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'.");

const s3 = new S3Client({ region: AWS_REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

const handler = async (event: APIGatewayProxyEventV2) => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { pathParameters: params } = event;

        if (!params || !params.id) {
            logger.error("Missing request path parameters.");

            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Missing required request fields." })
                .parse();
        }

        const id: string = params.id;

        const tokenResult = await ddb.send(new QueryCommand({
            TableName: REFRESH_TOKEN_TABLE,
            IndexName: "sub-index",
            KeyConditionExpression: "#sub = :sub",
            ExpressionAttributeNames: {
                "#sub": "sub"
            },
            ExpressionAttributeValues: {
                ":sub": id
            }
        }));

        const jtis = (tokenResult.Items ?? []).map(item => item.jti);

        await Promise.all(jtis.map(async jti => ddb.send(new DeleteCommand({
            TableName: REFRESH_TOKEN_TABLE,
            Key: { jti },
            ConditionExpression: "attribute_exists(jti)"
        }))));

        let token: string | undefined = undefined;

        do {
            const response: ListObjectsV2CommandOutput = await s3.send(new ListObjectsV2Command({
                Bucket: BUCKET,
                Prefix: path.posix.join("img", `pfp-${id}`),
                ContinuationToken: token
            }));

            const objects = response.Contents ?? [];

            if (objects.length === 0) break;

            await s3.send(new DeleteObjectsCommand({
                Bucket: BUCKET,
                Delete: {
                    Objects: objects.map(o => ({ Key: o.Key! }))
                }
            }));

            token = response.ContinuationToken;
        } while (token);

        try {
            await ddb.send(new DeleteCommand({
                TableName: USER_TABLE,
                Key: { id },
                ConditionExpression: "attribute_exists(id)"
            }));
        } catch (error) {
            if (error instanceof ConditionalCheckFailedException) {
                return new HttpResponse().status(HttpCode.NotFound)
                    .json({ message: "User not found." })
                    .parse();
            }
        }

        return new HttpResponse().status(HttpCode.NoContent)
            .parse();

    } catch (error) {
        logger.error(error);
        return new HttpResponse().status(HttpCode.InternalServerError)
            .json({ message: "Internal server error" })
            .parse();
    }
};

export { handler };