import { IsEmail, IsOptional, IsString, IsUrl } from "class-validator";

export class UpdateMemberRequest {
    @IsOptional()
    @IsString()
    public firstName?: string;

    @IsOptional()
    @IsString()
    public lastName?: string;

    @IsOptional()
    @IsString()
    public role?: string;

    @IsOptional()
    @IsString()
    public bio?: string;

    @IsOptional()
    @IsEmail()
    public email?: string;

    @IsOptional()
    @IsUrl()
    public profilePictureUrl?: string;

    @IsOptional()
    public since?: number;
}
