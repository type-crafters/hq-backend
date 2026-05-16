import { IsArray, IsEmail, IsNotEmpty, IsString } from "class-validator";

export class InviteUserRequest {
    @IsString()
    @IsNotEmpty()
    public firstName!: string;

    @IsString()
    @IsNotEmpty()
    public lastName!: string;

    @IsEmail()
    @IsNotEmpty()
    public email!: string;

    @IsArray()
    @IsNotEmpty()
    @IsString({ each: true })
    public permissions!: string[];
}