import assert from "assert";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { LoggerFactory, HttpResponse, HttpCode } from "@typecrafters/hq-lib";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { UploadType } from "./enum/UploadType.js";
import path from "path";
import { SignedUploadRequest } from "./interface/SignedUploadRequest.js";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const AWS_REGION = "us-east-1";
const BUCKET = process.env.BUCKET;

assert(BUCKET, "Missing required environment variable 'BUCKET'");

const s3 = new S3Client({ region: AWS_REGION });

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
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Missing required path parameters." })
                .parse();
        }

        const { upload, contentType }: SignedUploadRequest = JSON.parse(body);

        if (typeof upload !== "string" || !upload || typeof contentType !== "string" || !contentType) {
            logger.error("Body contains empty or malformed fields.")
            return new HttpResponse().status(HttpCode.BadRequest)
                .json({ message: "Body contains empty or malformed fields." })
                .parse();
        }


        if (Object.values(UploadType).includes(upload)) {
            let key: string = "";
            switch (upload) {
                case UploadType.ProfilePicture:
                    key = path.posix.join("img", `pfp-${id}.${contentType.split("/")[1]}`);
                    break;
                default:
                    logger.error("The declared type of the upload is not supported.")
                    return new HttpResponse().status(HttpCode.BadRequest)
                        .json({ message: "Cannot upload file of this type." })
                        .parse();
            }

            if (key) {
                const url = await getSignedUrl(s3, new PutObjectCommand({
                    Bucket: BUCKET,
                    Key: key,
                    ContentType: contentType
                }), { expiresIn: 60 });

                return new HttpResponse().status(HttpCode.OK)
                    .json({ url, key })
                    .parse();
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
