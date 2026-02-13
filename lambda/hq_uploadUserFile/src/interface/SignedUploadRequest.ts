import { UploadType } from "../enum/UploadType.js";

export interface SignedUploadRequest {
    upload: UploadType;
    contentType: string;
    [key: string]: unknown;
}