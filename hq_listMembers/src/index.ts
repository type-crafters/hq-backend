import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { type JSONResponse, type MemberItem, type ProjectItem, type ProjectResponse } from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, StringParser } from "@typecrafters/hq-lib";
import { DynamoDBDocumentClient, ScanCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const region = "us-east-1";
const MEMBER_TABLE = process.env.MEMBER_TABLE;
const BUCKET = process.env.BUCKET;

if (!MEMBER_TABLE) throw new Error("Missing required environment variable 'MEMBER_TABLE'.");
if (!BUCKET) throw new Error("Missing required environment variable 'BUCKET'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));
const s3 = new S3Client({ region });

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        let limit: number = 30;
        let cursor: Record<string, any> = {};
        const { queryStringParameters: params } = event;

        if (params) {
            const { limit: l, cursor: c } = params;
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
                    const cursorstr = Buffer.from(c, "base64url").toString("utf-8");
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
            TableName: MEMBER_TABLE,
            Limit: limit,
            ...(Object.keys(cursor).length && { ExclusiveStartKey: cursor })
        }));

        if (result.Items && result.Items.length) {
            const items = await Promise.all(result.Items.map(async (i) => {
                const item = i as MemberItem;
                let url: string = "";
                if (item.profilePictureUrl) {
                    url = await getSignedUrl(s3, new GetObjectCommand({
                        Bucket: BUCKET,
                        Key: item.profilePictureUrl
                    }), { expiresIn: 3600 });
                }
                return item;
            }));


            let newCursor: string = "";
            if (result.LastEvaluatedKey) {
                newCursor = Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString("base64url");
            }

            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({
                    success: true,
                    message: "Team members successfully retrieved.",
                    items,
                    ...(newCursor ? { cursor: newCursor } : {})
                } satisfies JSONResponse<MemberItem>)
                .build();
        } else {
            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({
                    success: true,
                    message: "No team members retrieved."
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