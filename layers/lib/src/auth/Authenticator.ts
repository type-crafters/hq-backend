import jwt from "jsonwebtoken";
import { RequiresEnvironment } from "../util/RequiresEnvironment.js";
import { createHmac } from "node:crypto";
import { InvalidTokenError } from "./InvalidTokenError.js";
import { ExpiredTokenError } from "./ExpiredTokenError.js";

type TokenType = "access" | "refresh";

interface AuthenticatorArgs<T extends TokenType> {
    environment: NodeJS.ProcessEnv;
    typ: T;
}

export class Authenticator<T extends TokenType> extends RequiresEnvironment {
    private typ: T;
    private static readonly ISS: string = "https://typecrafters.org";
    protected override required: Set<string> = new Set([
        "JTI_SECRET",
        "ACCESS_SECRET",
        "REFRESH_SECRET"
    ]);

    private get secret(): string {
        return this.getEnv(
            this.typ === "access" ? "ACCESS_SECRET" : "REFRESH_SECRET"
        ).strict().valueOf();
    }

    private constructor({ environment, typ }: AuthenticatorArgs<T>) {
        super(environment);
        this.typ = typ;
    }

    public static access(environment: NodeJS.ProcessEnv): Authenticator<"access"> {
        return new Authenticator({ environment, typ: "access" });
    }

    public static refresh(environment: NodeJS.ProcessEnv): Authenticator<"refresh"> {
        return new Authenticator({ environment, typ: "refresh" });
    }

    public issue(claims: Record<string, any>): Record<string, any> {
        return { ...claims, iss: Authenticator.ISS, typ: this.typ };
    }

    public sign(claims: Record<string, any>): string {
        try {
            return jwt.sign(this.issue(claims), this.secret, { algorithm: "HS256" });
        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                throw new InvalidTokenError("Invalid format for JWT Claims.", { cause: error });
            } else {
                throw error;
            }
        }
    }

    public getClaims(token: string): Record<string, any> {
        try {
            const claims = jwt.verify(token, this.secret);
            if (typeof claims === "string") return JSON.parse(claims);
            return claims;
        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                throw new InvalidTokenError(error.message, { cause: error });
            } else if (error instanceof jwt.TokenExpiredError) {
                throw new ExpiredTokenError("Token expired.", { cause: error });
            } else {
                throw error;
            }
        }
    }

    public getSub(token: string): string | undefined {
        const claims = this.getClaims(token);
        return claims["sub"] ?? undefined;
    }

    public getPermissions(token: string): string[] {
        const claims = this.getClaims(token);
        return claims["prm"] ?? [];
    }

    public hashJTI(claims: Record<string, any>): Record<string, any> {
        if (!claims["jti"] || typeof claims["jti"] !== "string") return claims;

        const jti = claims["jti"];

        const hash = createHmac("sha256", this.getEnv("JTI_SECRET").strict().valueOf())
            .update(jti)
            .digest("base64url");

        return { ...claims, jti: hash };
    }
}