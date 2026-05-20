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
import { UserStatus } from "@/user/dto/user-status.enum";

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(Session.name) private readonly sessionModel: Model<SessionDocument>,
        private readonly userService: UserService,
        private readonly tokenService: VerificationTokenService,
        private readonly mailService: MailService,
        private readonly config: ConfigService,
    ) { }

    private hashSessionId(jssessid: string): string {
        return createHash("sha256").update(jssessid).digest("hex");
    }

    public async authenticateUser(
        email: string,
        password: string,
        rememberMe: boolean,
        userAgent: string,
        ipAddress: string,
    ): Promise<string> {
        const unauthorized = new UnauthorizedException("Unauthorized.");
        const optionalUser = await this.userService.getByEmail(email);

        if (!optionalUser.isPresent()) throw unauthorized;

        const user = optionalUser.get();

        if (!user.password) throw unauthorized;

        if (!(await bcrypt.compare(password, user.password))) throw unauthorized;

        const jssessid = randomBytes(32).toString("base64url");
        const expiresAt = Duration.ofDays(rememberMe ? 90 : 7).fromNow();

        await this.sessionModel.create({
            jssessid: this.hashSessionId(jssessid),
            uid: user._id,
            userAgent,
            ipAddress,
            expiresAt,
        });

        return jssessid;
    }

    public async validateSession(
        jssessid: string,
        userAgent: string,
        ipAddress: string,
    ) {
        const unauthorized = new UnauthorizedException("Unauthorized.");

        if (!jssessid) throw unauthorized;

        const session = await this.sessionModel.findOne({
            jssessid: this.hashSessionId(jssessid),
        });

        if (!session) throw unauthorized;

        if (session.expiresAt.getTime() <= Date.now()) {
            await this.sessionModel.deleteOne({ _id: session._id });
            throw unauthorized;
        }

        if (session.userAgent !== userAgent || session.ipAddress !== ipAddress) {
            await this.sessionModel.deleteOne({ _id: session._id });
            throw unauthorized;
        }

        const optionalUser = await this.userService.get(session.uid.toString());

        if (!optionalUser.isPresent()) {
            await this.sessionModel.deleteOne({ _id: session._id });
            throw unauthorized;
        }

        await session.save();
        return optionalUser.get();
    }

    public async logout(jssessid: string): Promise<void> {
        await this.sessionModel.deleteOne({ jssessid: this.hashSessionId(jssessid) });
    }

    public async revokeUserSessions(uid: string): Promise<void> {
        await this.sessionModel.deleteMany({ uid: new Types.ObjectId(uid) });
    }

    // --- Account creation flow ---

    public async sendVerificationEmail(uid: string, email: string, firstName: string): Promise<void> {
        const token = await this.tokenService.createForEmail(uid);
        const url = new URL("/hq/users/email/verify", this.config.getOrThrow<string>("PAGE_URL"));
        url.searchParams.set("uid", uid);
        url.searchParams.set("token", token);

        await this.mailService.renderAndSend(email, "Verify your email address.", "verify-email.ejs", {
            url: url.toString(),
            firstName,
        });
    }

    public async activateUserAccount(
        uid: string,
        token: string,
        password: string,
        confirmPassword: string,
    ): Promise<void> {
        const unauthorized = new UnauthorizedException("Unauthorized.");

        if (!(await this.tokenService.validateEmailToken(token, uid))) throw unauthorized;

        if (password !== confirmPassword) throw new BadRequestException("Passwords do not match.");

        const optionalUser = await this.userService.get(uid);
        if (!optionalUser.isPresent()) throw unauthorized;

        const user = optionalUser.get();
        if (user.password) throw unauthorized; // already activated

        await this.userService.activateAccount(uid, password);
        await this.tokenService.consumeEmailToken(token, uid);
    }

    // --- Email verification flow (existing users) ---

    public async verifyEmail(uid: string, token: string): Promise<void> {
        const unauthorized = new UnauthorizedException("Unauthorized.");

        const optionalUser = await this.userService.get(uid);
        if (!optionalUser.isPresent()) throw unauthorized;

        if (!(await this.tokenService.validateEmailToken(token, uid))) throw unauthorized;

        await this.userService.setStatus(uid, UserStatus.Active);
        await this.tokenService.consumeEmailToken(token, uid);
    }

    // --- Password reset flow ---

    public async sendPasswordResetLink(email: string): Promise<void> {
        const optionalUser = await this.userService.getByEmail(email);
        if (!optionalUser.isPresent()) return; // silent no-op to prevent user enumeration

        const user = optionalUser.get();
        if (!user.password) return; // account not yet activated

        const uid = user._id.toString();
        const token = await this.tokenService.createForPassword(uid);
        const url = new URL("/password/reset", this.config.getOrThrow<string>("PAGE_URL"));
        url.searchParams.set("sub", uid);
        url.searchParams.set("token", token);

        await this.mailService.renderAndSend(email, "Your password reset request", "reset-password.ejs", {
            firstName: user.firstName,
            url: url.toString(),
        });
    }

    public async verifyPasswordResetToken(uid: string, token: string): Promise<{ sub: string }> {
        if (!(await this.tokenService.validatePasswordToken(token, uid))) {
            throw new BadRequestException("Unable to validate token.");
        }

        return { sub: uid };
    }

    public async resetUserPassword(
        uid: string,
        token: string,
        password: string,
        confirmPassword: string,
    ): Promise<void> {
        const unauthorized = new UnauthorizedException("Unauthorized.");

        if (!(await this.tokenService.validatePasswordToken(token, uid))) throw unauthorized;

        if (password !== confirmPassword) throw new BadRequestException("Passwords do not match.");

        await this.userService.updatePasswordById(uid, password);
        await this.tokenService.consumePasswordToken(token, uid);
    }
}