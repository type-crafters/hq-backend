import { Injectable } from "@nestjs/common";
import { createHash, randomBytes } from "crypto";
import { InjectModel } from "@nestjs/mongoose";
import type { Model } from "mongoose";
import { VerificationToken, type VerificationTokenDocument } from "./verification-token.schema";
import { TokenType } from "./dto/token-type.enum";
import { Duration } from "@/common/class/duration";

@Injectable()
export class VerificationTokenService {
    constructor(
        @InjectModel(VerificationToken.name) private readonly tokenModel: Model<VerificationTokenDocument>
    ) { }

    public hash(token: string): string {
        return createHash("sha256")
            .update(token)
            .digest("hex");
    }

    public async createForEmail(uid: string): Promise<string> {
        const ttl = Duration.ofDays(1).toSeconds();
        return await this.create(uid, TokenType.EmailVerification, ttl);
    }

    public async createForPassword(uid: string): Promise<string> {
        const ttl = Duration.ofHours(1).toSeconds()
        return await this.create(uid, TokenType.PasswordReset, ttl);
    }

    private async create(uid: string, type: TokenType, ttlSeconds: number): Promise<string> {
        const token = randomBytes(32).toString("hex");
        const hash = this.hash(token);
        const expiresAt = Duration.ofSeconds(ttlSeconds).fromNow();

        await this.tokenModel.create({
            hash,
            uid,
            type,
            expiresAt
        });

        return token;
    }

    public async isValidEmailToken(input: string, uid: string): Promise<boolean> {
        return await this.validate(input, uid, TokenType.EmailVerification);
    }

    public async isValidPasswordToken(input: string, uid: string): Promise<boolean> {
        return await this.validate(input, uid, TokenType.PasswordReset);
    }

    private async validate(input: string, uid: string, type: TokenType): Promise<boolean> {
        const hash = this.hash(input);
        const token = await this.tokenModel.findOne({ hash });

        if (!token) {
            return false;
        }

        const expired = token.expiresAt.getTime() <= Date.now();

        if (expired) {
            await this.tokenModel.deleteOne({ _id: token.id});
            return false;
        }

        if (token.type !== type) {
            return false;
        }

        if (token.uid !== uid) {
            return false;
        }

        await this.tokenModel.deleteMany({ uid, type });
        return true;
    }
}