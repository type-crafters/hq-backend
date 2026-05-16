import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import bcrypt from "bcrypt";
import { createHash, randomBytes } from "crypto";
import { ConfigService } from "@nestjs/config";
import { InjectModel } from "@nestjs/mongoose";
import { Types, type Model } from "mongoose";
import { UserService } from "@/user/user.service";
import { MailService } from "@/mail/mail.service";
import { Duration } from "@/common/class/duration";
import { Session, type SessionDocument } from "./session.schema";
import { VerificationTokenService } from "@/verification-token/verification-token.service";

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(Session.name) private readonly sessionModel: Model<SessionDocument>,
        private readonly userService: UserService,
        private readonly tokenService: VerificationTokenService,
        private readonly mailService: MailService,
        private readonly config: ConfigService
    ) { }

    private hashSessionid(jssessid: string): string {
        return createHash("sha256")
            .update(jssessid)
            .digest("hex");
    }

    public async authenticateUser(
        email: string,
        password: string,
        rememberMe: boolean,
        userAgent: string,
        ipAddress: string
    ): Promise<string> {
        const unauthorized = new UnauthorizedException("Unauthorized.");
        const optionalUser = await this.userService.getByEmail(email);

        if (!optionalUser.isPresent()) {
            throw unauthorized;
        }

        const user = optionalUser.get();

        if (!(await bcrypt.compare(password, user.password))) {
            throw unauthorized;
        }

        const jssessid = randomBytes(32).toString("base64url");
        const expiresAt = Duration.ofDays(rememberMe ? 90 : 7).fromNow();

        await this.sessionModel.create({
            jssessid: this.hashSessionid(jssessid),
            uid: user.id,
            userAgent,
            ipAddress,
            expiresAt,
        });
        
        return jssessid;
    }

    public async validateSession(
        jssessid: string,
        userAgent: string,
        ipAddress: string
    ) {
        const unauthorized = new UnauthorizedException("Unauthorized.");

        if (!jssessid) {
            throw unauthorized;
        }

        const session = await this.sessionModel.findOne({
            jssessid:  this.hashSessionid(jssessid)
        });

        if (!session) {
            throw unauthorized;
        }

        if (session.expiresAt.getTime() <= Date.now()) {
            await this.sessionModel.deleteOne({ _id: session._id });
            throw unauthorized;
        }

        if (session.userAgent !== userAgent || session.ipAddress !== ipAddress) {
            await this.sessionModel.deleteOne({ _id: session._id });
            throw unauthorized;
        }

        const optionalUser = await this.userService.getById(
                session.uid.toString()
            );

        if (!optionalUser.isPresent()) {
            await this.sessionModel.deleteOne({ _id: session._id });

            throw unauthorized;
        }

        await session.save();
        return optionalUser.get();
    }

    public async logout(jssessid: string): Promise<void> {
        await this.sessionModel.deleteOne({
            jssessid:
                this.hashSessionid(jssessid)
        });
    }

    public async revokeUserSessions(uid: string): Promise<void> {
        await this.sessionModel.deleteMany({ uid: new Types.ObjectId(uid) });
    }

    public async verifyEmail(
        sub: string,
        token: string
    ): Promise<void> {
        const badRequest =
            new BadRequestException(
                "Unable to validate token."
            );

        const isValid =
            await this.tokenService
                .isValidEmailToken(token, sub);

        if (!isValid) {
            throw badRequest;
        }

        const updated =
            await this.userService
                .activateById(sub);

        if (!updated.isPresent()) {
            throw badRequest;
        }
    }

    public async sendPasswordResetLink(email: string): Promise<void> {
        const optionalUser = await this.userService.getByEmail(email);

        if (!optionalUser.isPresent()) {
            return;
        }

        const user = optionalUser.get();
        const sub = user.id.toString();
        const token = await this.tokenService.createForPassword(sub);

        const url = new URL(
            "/password/reset",
            this.config.getOrThrow("PAGE_URL")
        );

        url.searchParams.set("sub", sub);

        url.searchParams.set(
            "token",
            token
        );

        await this.mailService.renderAndSend(
            email,
            "Your password reset request",
            "reset-password.ejs",
            {
                firstName: user.firstName,

                url: url.toString()
            }
        );
    }

    public async verifyPasswordReset( sub: string, token: string) {
        const badRequest = new BadRequestException("Unable to validate token.");

        const isValid = await this.tokenService .isValidPasswordToken(token, sub);

        if (!isValid) {
            throw badRequest;
        }

        return { sub };
    }

    public async resetUserPassword(id: string, password: string, confirmPassword: string): Promise<void> {
        if (password !== confirmPassword) {
            throw new BadRequestException("Passwords do not match.");
        }

        const hash = await bcrypt.hash(password, 10);
        await this.userService.updatePasswordById(id, hash);
    }
}
