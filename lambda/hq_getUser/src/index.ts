import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
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
        const params = event.pathParameters;

        if (!params || !params["id"]) {
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "No 'id' parameter provided." })
                .parse();
        }

        const id: string = params["id"];

        try {
            const result = await ddb.send(new GetCommand({
                TableName: USER_TABLE,
                Key: { id }
            }));

            const user = result.Item;

            if (!user || !Object.keys(user).length) {
                return new HttpResponse().status(HttpCode.NotFound)
                    .json({ message: "User not found" })
                    .parse();
            }

            if (user.profilePictureUrl) {
                user.profilePictureUrl = await getSignedUrl(s3, new GetObjectCommand({
                    Bucket: BUCKET,
                    Key: user.profilePictureUrl
                }), { expiresIn: 3600 });
            }

            return new HttpResponse().status(HttpCode.OK)
                .json({ message: "User retrieved", user })
                .parse();

        } catch (error) {
            logger.error("There was an error retrieving the user from the database.");
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
