import { IsEmail, IsNotEmpty, IsOptional, IsString, IsUrl } from "class-validator";

export class CreateMemberRequest {
    @IsString()
    @IsNotEmpty()
    public firstName!: string;

    @IsString()
    @IsNotEmpty()
    public lastName!: string;

    @IsString()
    @IsNotEmpty()
    public role!: string;

    @IsOptional()
    @IsString()
    public bio?: string;

    @IsEmail()
    @IsNotEmpty()
    public email!: string;

    @IsOptional()
    @IsUrl()
    public profilePictureUrl?: string;

    @IsNotEmpty()
    public since!: number;
}
