import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";
import { HttpCode, HttpResponse, LoggerFactory } from "@typecrafters/hq-lib";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import assert from "assert";

const AWS_REGION = "us-east-1";
const BUCKET = process.env.BUCKET;
const USER_TABLE = process.env.USER_TABLE;

assert(BUCKET, "Missing required environment variable 'BUCKET'");
assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'");

const s3 = new S3Client({ region: AWS_REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

const handler = async (event: APIGatewayProxyEventV2) => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        let limit: number = 30;
        let cursor: Record<string, any> = {};

        let params = event.queryStringParameters;

        if (params) {
            const pLimit = params["limit"];
            const pCursor = params["cursor"];
            if (pLimit && !isNaN(parseInt(pLimit))) {
                limit = parseInt(pLimit);
            }
            if (pCursor) {
                cursor = JSON.parse(Buffer.from(pCursor, "base64").toString("utf-8"));
            }
        }
        try {
            const result = await ddb.send(new ScanCommand({
                TableName: USER_TABLE,
                Limit: limit,
                ...(Object.keys(cursor).length && { ExclusiveStartKey: cursor })
            }));

            if (result.Items && result.Items.length) {
                const items = await Promise.all(result.Items.map(async (i) => {
                    const url = await getSignedUrl(s3, new GetObjectCommand({
                        Bucket: BUCKET,
                        Key: i.profilePictureUrl
                    }), { expiresIn: 3600 });

                    return { 
                        ...i,
                        password: !!i.password,
                        profilePictureUrl: url,
                        permissions: Array.from(i.permissions)
                    };
                }));

                let newCursor: string = "";
                
                if (result.LastEvaluatedKey) {
                    newCursor = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString("base64");
                }

                return new HttpResponse().status(HttpCode.OK)
                    .json({ cursor: newCursor, items })
                    .parse();
            } else {
                return new HttpResponse().status(HttpCode.NotFound)
                    .json({ message: "Not Found" })
                    .parse();
            }
        } catch (error) {
            logger.error("An error occurred while querying DynamoDB");
            throw error;
        }
        

    } catch (error) {
        logger.error(error);
        return new HttpResponse().status(HttpCode.InternalServerError)
            .json({ message: "Internal server error." })
            .parse();
    }
};

export { handler };
