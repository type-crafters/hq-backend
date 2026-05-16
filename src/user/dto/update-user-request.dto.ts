import { IsString, IsEmail, IsOptional, IsArray } from 'class-validator';
import { Type } from 'class-transformer';

export class UpdateUserRequest {
    @IsOptional()
    @IsString()
    firstName?: string;

    @IsOptional()
    @IsString()
    lastName?: string;

    @IsOptional()
    @IsEmail()
    email?: string;

    @IsOptional()
    @IsString()
    password?: string;

    @IsOptional()
    @IsString()
    profilePictureUrl?: string;

    @IsOptional()
    @IsString()
    status?: string;

    @IsOptional()
    @IsArray()
    @Type(() => String)
    permissions?: string[];
}