import { Body, Controller, Get, HttpCode, Post, Query, Res } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { LoginRequest } from "./dto/login-request.dto";
import { ForgotPasswordRequest } from "./dto/forgot-password-request";
import { ResetPasswordRequest } from "./dto/reset-password-request.dto";
import type { Response } from "express";
import { ClientInfo } from "@/common/decorator/client-info.decorator";
import { User } from "@/common/decorator/user.decorator";

@Controller("auth")
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post("login")
    public async login(
        @Body() body: LoginRequest,
        @ClientInfo("ipAddress") ipAddress: string,
        @ClientInfo("userAgent") userAgent: string,
        @Res({ passthrough: true }) response: Response
    ) {
        const { accessToken, refreshToken } = await this.authService.authenticateUser(
            body.email,
            body.password,
            body.rememberMe,
            userAgent,
            ipAddress
        );

        response.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "none",
            maxAge: (body.rememberMe ? 90 : 7) * 86_400 * 1_000
        });

        return { accessToken }
    }

    @Post("email/verify")
    public async verifyAccount(@Query("sub") sub: string, @Query("token") token: string) {
        await this.authService.verifyEmail(sub, token);
    }

    @Get("refresh")
    public async refreshSession() {

    }

    @HttpCode(200)
    @Post("password/forgot")
    public async sendPasswordResetLink(@Body() body: ForgotPasswordRequest) {
        await this.authService.sendPasswordResetLink(body.email);
    }

    @HttpCode(200)
    @Post("password/verify")
    public async verifyPasswordResetLink(@Query("sub") sub: string, @Query("token") token: string) {
        return await this.authService.verifyPasswordReset(sub, token);
    }

    @Post("password/reset")
    public async updatePassword(@Body() body: ResetPasswordRequest) {
        await this.authService.resetUserPassword(body.id, body.password, body.confirmPassword);
    }

    @Post("logout")
    public async logout(
        @User("id") id: string, 
        @ClientInfo("ipAddress") 
        ipAddress: string, 
        @Res() response: Response
    ) {
        await this.authService.revokeUserSession(id, ipAddress);
        response.clearCookie("refreshToken", { httpOnly: true, secure: true, sameSite: "none" });
    }
}