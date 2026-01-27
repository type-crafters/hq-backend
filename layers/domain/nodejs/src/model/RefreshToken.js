import { randomUUID } from "crypto";
import { AuthToken } from "./AuthToken";

export class RefreshToken extends AuthToken {
    constructor({
        jti,
        exp,
        iat,
        sub
    } = {}) {
        super({ jti, exp, iat, sub });
        this.typ = "refresh";
    }

    toJSON() {
        return {
            jti: this.jti,
            exp: Math.floor(this.exp.getTime() / 1000),
            iat: Math.floor(this.iat.getTime() / 1000),
            iss: this.iss,
            sub: this.sub,
            typ: this.typ
        };
    }

    static fromClaims(claims) {
        const {
            exp,
            iat,
            sub
        } = claims;

        return new RefreshToken({
            jti: randomUUID(),
            exp: new Date(typeof exp === "number" ? exp * 1000 : exp),
            iat: new Date(typeof iat === "number" ? iat * 1000 : iat),
            sub
        });
    }
}