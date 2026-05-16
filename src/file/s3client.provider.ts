import type { Provider } from "@nestjs/common";
import { S3_CLIENT } from "./constants";
import { ConfigService } from "@nestjs/config";
import { S3Client } from "@aws-sdk/client-s3";

export const S3ClientProvider: Provider<S3Client> = {
    provide: S3_CLIENT,
    inject: [ConfigService],
    useFactory: (config: ConfigService) => new S3Client({
        endpoint: config.getOrThrow("S3_ENDPOINT"),
        region: "us-east-1",
        credentials: {
            accessKeyId: config.getOrThrow("S3_KEY_ID"),
            secretAccessKey: config.getOrThrow("S3_KEY")
        },
        forcePathStyle: true
    })
};