import { IsBoolean, IsEmail, IsNotEmpty, IsString } from "class-validator";
import { NormalizeEmail } from "@/common/decorator/normalize-email.decorator";

export class LoginRequest {
    @NormalizeEmail()
    @IsEmail()
    @IsNotEmpty()
    public email!: string;

    @IsString()
    @IsNotEmpty()
    public password!: string;

    @IsBoolean()
    public rememberMe!: boolean;
}