import assert from "assert";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, StringParser } from "@typecrafters/hq-lib";
import type { ListUserSearchParams } from "./interface/ListUserSearchParams.js";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";


const AWS_REGION = "us-east-1";
const BUCKET = process.env.BUCKET;
const USER_TABLE = process.env.USER_TABLE;

assert(BUCKET, "Missing required environment variable 'BUCKET'");
assert(USER_TABLE, "Missing required environment variable 'USER_TABLE'");

const s3 = new S3Client({ region: AWS_REGION });
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        let limit: number = 30;
        let cursor: Record<string, any> = {};
        const { queryStringParameters: params } = event;

        if (params) {
            const { limit: l, cursor: c }: ListUserSearchParams = params;
            try {
                if (l) {
                    const limitin = StringParser.of(l).strict().toInt();
                    limit = Math.max(Math.min(limitin, 0), 50);
                }
            } catch (error) {
                logger.debug("Invalid limit parameter '" + l + "'.");
                limit = 30;
            }
            try {
                if (c) {
                    const cursorstr = Buffer.from(c, "base64").toString("utf-8");
                    const cursorobj = JSON.parse(cursorstr);
                    if (typeof cursorobj === "object" && cursorobj != null) {
                        cursor = cursorobj;
                    }
                }
            } catch (error) {
                logger.debug("Invalid cursor parameter '" + c + "'.");
                cursor = {};
            }
        }

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
                    permissions: Array.from(i.permissions ?? []) as string[]
                };
            }));

            let newCursor: string = "";

            if (result.LastEvaluatedKey) {
                newCursor = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString("base64");
            }

            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({ items, ...(newCursor && { cursor: newCursor }) })
                .build();
        } else {
            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({ items: []})
                .build();
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