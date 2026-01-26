import { AuthToken } from "./AuthToken";

export declare interface AccessTokenArgs {
    jti: string;
    email: string;
    exp: Date;
    iat: Date;
    roles: string[];
    sub: string;
}

export declare class AccessToken extends AuthToken {
    email: string;
    roles: string;
    override typ: "access";

    constructor({
        jti,
        email,
        exp,
        iat,
        roles,
        sub,
    }: AccessTokenArgs);
}