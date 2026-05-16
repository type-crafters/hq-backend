import { GetObjectCommand, PutObjectCommand, type S3Client } from "@aws-sdk/client-s3";
import { Inject, Injectable, NotAcceptableException } from "@nestjs/common";
import { S3_CLIENT } from "./constants";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { ConfigService } from "@nestjs/config";
import { randomUUID } from "node:crypto";
import { SignedUploadLinkRequest } from "./dto/signed-upload-link-request.dto";
import { UploadType } from "./dto/upload-type.enum";
import path from "node:path";
import { SignedUploadLinkResponse } from "./dto/signed-upload-link-response.dto";
import { Space } from "@/common/util/space";

@Injectable()
export class FileService {
    private static readonly MAX_IMAGE_SIZE = Space.ofMegabytes(5).toBytes();
    private readonly BUCKET: string;
    constructor(@Inject(S3_CLIENT) private readonly s3: S3Client, private readonly config: ConfigService) {
        this.BUCKET = this.config.getOrThrow<string>("S3_BUCKET");
    }

    public get placeholder(): string {
        return path.posix.join("system", "placeholder.svg");
    }

    public isSystemFile(key: string): boolean {
        return key.trim().startsWith("system/");
    }

    public async getSignedUploadUrl(body: SignedUploadLinkRequest): Promise<SignedUploadLinkResponse> {
        let Key: string = "";
        const fragments: string[] = [];
        const checks: ((body: SignedUploadLinkRequest) => boolean)[] = [];

        switch (body.type) {
            case UploadType.ProfilePicture:
                fragments.push("user");
                checks.push(body => body.contentType.trim().startsWith("image/"));
                checks.push((({ length }) => 0 < length && length <= FileService.MAX_IMAGE_SIZE));
                break;
            case UploadType.ProjectThumbnail:
                checks.push(body => body.contentType.trim().startsWith("image/"));
                checks.push((({ length }) => 0 < length && length <= FileService.MAX_IMAGE_SIZE));
                fragments.push("project");
                break;
            case UploadType.TeamMemberPicture:
                checks.push(body => body.contentType.trim().startsWith("image/"));
                checks.push((({ length }) => 0 < length && length <= FileService.MAX_IMAGE_SIZE));
                fragments.push("team");
                break;
            case UploadType.BlogPostText:
                fragments.push("blog");
                checks.push(body => body.contentType.trim().startsWith("text/"));
                break;
            case UploadType.BlogPostImage:
                fragments.push("blog");
                checks.push(body => body.contentType.trim().startsWith("image/"));
                checks.push((({ length }) => 0 < length && length <= FileService.MAX_IMAGE_SIZE));
                break;
        }

        if (checks.some(c => !c(body))) throw new NotAcceptableException("Content did not match restrictions.");

        const ext = path.extname(body.filename) || ".bin";
        fragments.push(body.ownerId, `${randomUUID()}${ext}`);

        console.log({ body });
        console.log({ fragments });

        Key = path.posix.join(...fragments);

        const url = await getSignedUrl(this.s3, new PutObjectCommand({
            Bucket: this.BUCKET,
            Key,
            ContentType: body.contentType,
            ContentLength: body.length
        }), { expiresIn: 60 });

        return SignedUploadLinkResponse.of(Key, url);
    }

    public async getSignedUrl(key: string): Promise<string> {
        return await getSignedUrl(this.s3, new GetObjectCommand({
            Bucket: this.BUCKET,
            Key: key
        }), { expiresIn: 3600 });
    }
}