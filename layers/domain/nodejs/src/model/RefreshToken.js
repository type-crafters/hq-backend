import { creeateHmac } from "crypto";
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

    toItem() {
        return {
            jti: this.jti,
            exp: Math.floor(this.exp.getTime() / 1000),
            iat: Math.floor(this.iat.getTime() / 1000),
            iss: this.iss,
            sub: this.sub,
            typ: this.typ
        };
    }
}