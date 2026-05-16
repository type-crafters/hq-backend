import { IsEnum, IsInt, IsMimeType, IsNotEmpty, IsPositive, IsString } from "class-validator";
import { UploadType } from "./upload-type.enum";

export class SignedUploadLinkRequest {
    @IsString()
    @IsNotEmpty()
    public filename!: string;

    @IsMimeType()
    @IsNotEmpty()
    public contentType!: string;

    @IsInt()
    @IsPositive()
    public length!: number;

    @IsEnum(UploadType)
    @IsNotEmpty()
    public type!: UploadType;

    @IsString()
    @IsNotEmpty()
    public ownerId!: string;
}