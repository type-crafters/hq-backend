import { IsEmail, IsNotEmpty } from "class-validator";

export class ForgotPasswordRequest {
    @IsEmail()
    @IsNotEmpty()
    public email!: string;
}