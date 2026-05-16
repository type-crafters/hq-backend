import { Module } from "@nestjs/common";
import { FileController } from "./file.controller";
import { FileService } from "./file.service";
import { S3ClientProvider } from "./s3client.provider";

@Module({
    imports: [],
    controllers: [FileController],
    providers: [FileService, S3ClientProvider],
    exports: [FileService]
})
export class FileModule { }