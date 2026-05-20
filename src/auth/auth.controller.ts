import { Body, Controller, HttpCode, Post, Query, Res, HttpException, InternalServerErrorException } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { LoginRequest } from "./dto/login-request.dto";
import { ForgotPasswordRequest } from "./dto/forgot-password-request";
import { ResetPasswordRequest } from "./dto/reset-password-request.dto";
import type { Response } from "express";
import { Client } from "@/common/decorator/client-info.decorator";
import { User } from "@/common/decorator/user.decorator";
import { ItemResponse } from "@/common/dto/item-response.dto";

@Controller("auth")
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @Post("login")
    public async login(
        @Body() body: LoginRequest,
        @Client("ipAddress") ipAddress: string,
        @Client("userAgent") userAgent: string,
        @Res({ passthrough: true }) response: Response
    ) {
        try {
            const jssessid = await this.authService.authenticateUser(
                body.email,
                body.password,
                body.rememberMe,
                userAgent,
                ipAddress
            );

            response.cookie("jssessid", jssessid, {
                httpOnly: true,
                secure: true,
                sameSite: "none",
                maxAge: (body.rememberMe ? 90 : 7) * 86_400 * 1_000
            });

            const res = ItemResponse.OK();
            res.message = "Login successful.";
            return res;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException("An unexpected error occurred while logging in.", { cause: error });
        }
    }

    @HttpCode(200)
    @Post("email/verify")
    public async verifyAccount(@Query("uid") uid: string, @Query("token") token: string) {
        try {
            await this.authService.verifyEmail(uid, token);
            const res = ItemResponse.OK();
            res.message = "Email verified successfully.";
            return res;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException("An unexpected error occurred while verifying email.", { cause: error });
        }
    }

    @HttpCode(200)
    @Post("password/forgot")
    public async sendPasswordResetLink(@Body() body: ForgotPasswordRequest) {
        try {
            await this.authService.sendPasswordResetLink(body.email);
            const res = ItemResponse.OK();
            res.message = "If an account exists, a password reset link has been sent.";
            return res;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException("An unexpected error occurred while sending password reset link.", { cause: error });
        }
    }

    @HttpCode(200)
    @Post("password/verify")
    public async verifyPasswordResetLink(@Query("uid") uid: string, @Query("token") token: string) {
        try {
            const data = await this.authService.verifyPasswordResetToken(uid, token);
            const res = ItemResponse.OK();
            res.message = "Password reset token is valid.";
            res.data = data;
            return res;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException("An unexpected error occurred while verifying password reset token.", { cause: error });
        }
    }

    @Post("password/reset")
    public async updatePassword(@Body() body: ResetPasswordRequest, @Query("uid") uid: string, @Query("token") token: string) {
        try {
            await this.authService.resetUserPassword(uid, token, body.password, body.confirmPassword);
            const res = ItemResponse.OK();
            res.message = "Password updated successfully.";
            return res;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException("An unexpected error occurred while resetting the password.", { cause: error });
        }
    }

    @Post("logout")
    public async logout(@User("id") id: string, @Res({ passthrough: true }) response: Response) {
        try {
            await this.authService.revokeUserSessions(id);
            response.clearCookie("jssessid", { httpOnly: true, secure: true, sameSite: "none", path: "/" });
            const res = ItemResponse.OK();
            res.message = "Logged out successfully.";
            return res;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException("An unexpected error occurred while logging out.", { cause: error });
        }
    }
}