import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { type JSONResponse, type MemberItem } from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject } from "@typecrafters/hq-lib";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
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
        const { pathParameters } = event;

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

        const result = await ddb.send(new GetCommand({
            TableName: MEMBER_TABLE,
            Key: { id }
        }));

        if (!result.Item) {
            return HttpResponse.builder()
                .status(HttpCode.NotFound)
                .json({
                    success: false,
                    message: "Team member not found."
                } satisfies JSONResponse)
                .build();
        }

        const item = result.Item as MemberItem;


        if (item.profilePictureUrl) {
            const url = await getSignedUrl(s3, new GetObjectCommand({
                Bucket: BUCKET,
                Key: item.profilePictureUrl
            }), { expiresIn: 3600 });

            item.profilePictureUrl = url;
        }

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .json({
                success: true,
                message: "Team member successfully retrieved.",
                item: { ...item }
            } satisfies JSONResponse<MemberItem>)
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