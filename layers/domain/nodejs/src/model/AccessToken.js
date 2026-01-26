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
        super(jti, exp, iat, roles, sub);
        this.email = email;
        this.roles = roles;
        this.typ = "access";
    }
}