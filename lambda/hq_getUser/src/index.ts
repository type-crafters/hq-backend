import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { LoggerFactory, HttpResponse, HttpCode, type ResponseObject } from "@typecrafters/hq-lib";
import assert from "assert";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import type { User } from "./interface/User.js";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import type { UserResponse } from "./interface/UserResponse.js";

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
        const { pathParameters: params } = event;

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

        const result = await ddb.send(new GetCommand({
            TableName: USER_TABLE,
            Key: { id }
        }));

        if (!result || !result.Item || !Object.keys(result.Item).length) {
            return HttpResponse.builder()
                .status(HttpCode.NotFound)
                .text("User not found.")
                .build();
        }

        const user = result.Item as User;

        const response: UserResponse = {
            ...user,
            password: !!user.password,
            permissions: Array.from(user.permissions ?? [])
        };

        if (response.profilePictureUrl) {
            response.profilePictureUrl = await getSignedUrl(s3, new GetObjectCommand({
                Bucket: BUCKET,
                Key: response.profilePictureUrl
            }), { expiresIn: 3600 });
        }

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .json(response)
            .build();
    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .text("Internal server error.")
            .build();
    }
};

export { handler };