import { IsDateString, IsEmail, IsNotEmpty, IsString } from "class-validator";

export class SendMessageRequest {
    @IsString()
    @IsNotEmpty()
    public firstName!: string;

    @IsString()
    @IsNotEmpty()
    public lastName!: string;

    @IsEmail()
    @IsNotEmpty()
    public email!: string;

    @IsString()
    @IsNotEmpty()
    public subject!: string;

    @IsString()
    @IsNotEmpty()
    public message!: string;

    
    @IsDateString()
    @IsNotEmpty()
    public sentAt!: string;
}