import  { Body, Controller, Get } from "@nestjs/common";
import  { FileService } from "./file.service";
import { RequiresPermission } from "@/common/decorator/requires-permission.decorator";
import type { SignedUploadLinkRequest } from "./dto/signed-upload-link-request.dto";
import type { SignedUploadLinkResponse } from "./dto/signed-upload-link-response.dto";

@Controller("file")
export class FileController {
    constructor(private readonly fileService: FileService) { }

    @Get("upload")
    @RequiresPermission("put:file")
    public async getSignedUploadLink(@Body() body: SignedUploadLinkRequest): Promise<SignedUploadLinkResponse> {
        return this.fileService.getSignedUploadUrl(body);
    }
}