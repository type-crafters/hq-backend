import { randomUUID } from "crypto";
import { AuthToken } from "./AuthToken";

export class AccessToken extends AuthToken {
    email;
    roles;

    constructor({
        jti,
        email,
        exp,
        iat,
        roles,
        sub,
    } = {}) {
        super({ jti, exp, iat, sub });
        this.email = email;
        this.roles = roles;
        this.typ = "access";
    }

    toJSON() {
        return {
            jti: this.jti,
            email: this.email,
            exp: Math.floor(this.exp.getTime() / 1000),
            iat: Math.floor(this.iat.getTime() / 1000),
            iss: this.iss,
            roles: this.roles,
            sub: this.sub,
            typ: this.typ
        }
    }

    static fromClaims(claims) {
        const {
            email,
            exp,
            iat,
            roles,
            sub
        } = claims;

        return new AccessToken({
            jti: randomUUID(),
            email,
            exp: new Date(typeof exp === "number" ? exp * 1000 : exp),
            iat: new Date(typeof iat === "number" ? iat * 1000 : iat),
            roles,
            sub
        });
    }
}