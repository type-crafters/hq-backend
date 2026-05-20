import { IsNotEmpty, IsString, IsUUID } from "class-validator";

export class ResetPasswordRequest {
    @IsString()
    @IsNotEmpty()
    public password!: string;

    @IsString()
    @IsNotEmpty()
    public confirmPassword!: string;
}