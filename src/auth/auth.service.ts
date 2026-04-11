import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { UserService } from "@/user/user.service";
import bcrypt from "bcrypt";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { InjectRepository } from "@nestjs/typeorm";
import { RefreshToken } from "./refresh-token.entity";
import { MongoRepository } from "typeorm";
import { randomUUID } from "node:crypto";
import type { AccessClaims } from "@/common/interface/access-claims.interface";
import { VerificationTokenService } from "@/verification-token/verification-token.service";
import { MailService } from "@/mail/mail.service";

@Injectable()
export class AuthService {
    constructor(
        @InjectRepository(RefreshToken) private readonly refreshTokenRepository: MongoRepository<RefreshToken>,
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly tokenService: VerificationTokenService,
        private readonly mailService: MailService,
        private readonly config: ConfigService
    ) { }

    public async authenticateUser(
        email: string,
        password: string,
        rememberMe: boolean,
        userAgent: string,
        ipAddress: string
    ) {
        const unauthorized = new UnauthorizedException("Unauthorized.");
        const user = await this.userService.getByEmail(email);

        if (user === null) throw unauthorized;
        if (!(await bcrypt.compare(password, user.password))) throw unauthorized;

        const payload = {
            id: user.id.toString(),
            email: user.email,
            permissions: user.permissions
        } satisfies AccessClaims;


        const accessToken = await this.jwtService.signAsync(payload);

        const jti = randomUUID();
        const ttl = (rememberMe ? 90 : 7) * 86_400;
        const refreshToken = await this.jwtService.signAsync(payload, {
            secret: this.config.getOrThrow("REFRESH_SECRET"),
            expiresIn: ttl,
            jwtid: jti
        });

        await this.refreshTokenRepository.save(
            this.refreshTokenRepository.create({
                sub: user.id.toString(),
                jti,
                expiresAt: new Date(Date.now() + ttl * 1_000),
                ipAddress,
                userAgent
            })
        );

        return { accessToken, refreshToken };
    }

    public async verifyEmail(sub: string, token: string) {
        const badRequest = new BadRequestException("Unable to validate token.");
        const isValid = await this.tokenService.isValidEmailToken(token, sub);

        if (!isValid) throw badRequest;

        try {
            await this.userService.activateById(sub);
        } catch (error) {
            if (error instanceof NotFoundException) throw badRequest;
            throw new InternalServerErrorException("Failed to activate user account.");
        }
    }

    public async sendPasswordResetLink(email: string) {
        const user = await this.userService.getByEmail(email);
        if (user !== null) {
            const sub = user.id.toString();
            const token = await this.tokenService.createForPassword(sub);

            const url = new URL("/password/reset", this.config.getOrThrow("PAGE_URL"));

            url.searchParams.set("sub", sub);
            url.searchParams.set("token", token);

            await this.mailService.renderAndSend(
                email,
                "Your password reset request",
                "reset-password.ejs",
                { firstName: user.firstName, url: url.toString() }
            );
        }
    }

    public async verifyPasswordReset(sub: string, token: string) {
        const badRequest = new BadRequestException("Unable to validate token.");
        const isValid = await this.tokenService.isValidPasswordToken(token, sub);

        if (!isValid) throw badRequest;

        return { sub };
    }

    public async resetUserPassword(id: string, password: string, confirmPassword: string) {
        if (password !== confirmPassword)
            throw new BadRequestException("Passwords do not match.");

        const hash = await bcrypt.hash(password, 10);

        this.userService.updatePasswordById(id, hash);
    }

    public async revokeUserSession(id: string, ipAddress: string) {
        await this.refreshTokenRepository.delete({ sub: id, ipAddress })
    }
}