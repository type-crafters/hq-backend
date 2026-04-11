import { Injectable } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { createHash, randomBytes } from "crypto";
import { VerificationToken } from "./verification-token.entity";
import { MongoRepository } from "typeorm";
import { TokenType } from "./token-type.enum";

@Injectable()
export class VerificationTokenService {
    constructor(@InjectRepository(VerificationToken) private readonly tokenRepository: MongoRepository<VerificationToken>) { }

    public hash(token: string): string {
        return createHash("sha256").update(token).digest("hex");
    }

    public async createForEmail(sub: string): Promise<string> {
        const random = randomBytes(32).toString("hex");
        const hash = this.hash(random);

        const token = this.tokenRepository.create({
            hash,
            sub,
            type: TokenType.EmailVerification,
            expiresAt: new Date(Date.now() + 86_400 * 1_000)
        });

        await this.tokenRepository.save(token);
        return random;
    }

    public async createForPassword(sub: string): Promise<string> {
        const random = randomBytes(32).toString("hex");
        const hash = this.hash(random);

        const token = this.tokenRepository.create({
            hash,
            sub,
            type: TokenType.PasswordReset,
            expiresAt: new Date(Date.now() + 3_600 * 1_000)
        });

        await this.tokenRepository.save(token);
        return random;
    }

    public async isValidEmailToken(input: string, sub: string): Promise<boolean> {
        const hash = this.hash(input);

        const token = await this.tokenRepository.findOneBy({ hash });

        const now = new Date();

        if (!token) return false;
        if (token.expiresAt < now) return false;
        if (token.type !== TokenType.EmailVerification) return false;
        if (token.sub !== sub) return false;

        await this.tokenRepository.delete({
            sub,
            type: TokenType.EmailVerification
        });

        return true;
    }

    public async isValidPasswordToken(input: string, sub: string): Promise<boolean> {
        const hash = this.hash(input);

        const token = await this.tokenRepository.findOneBy({ hash });

        const now = new Date();

        if (!token) return false;
        if (token.expiresAt < now) return false;
        if (token.type !== TokenType.PasswordReset) return false;
        if (token.sub !== sub) return false;

        await this.tokenRepository.delete({
            sub,
            type: TokenType.PasswordReset
        });

        return true;
    }
}