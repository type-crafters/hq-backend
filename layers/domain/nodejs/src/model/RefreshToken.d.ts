import { AuthToken } from "./AuthToken";

export declare interface RefreshTokenArgs {
    jti: string;
    exp: Date;
    iat: Date;
    sub: string;
}

export declare interface RefreshTokenItem {
    jti: string;
    exp: number;
    iat: number;
    iss: string;
    sub: string;
    typ: "access" | "refresh";
    [key: string]: unknown;
}


export declare class RefreshToken extends AuthToken {
    constructor({
        jti,
        exp,
        iat,
        sub
    }: RefreshTokenArgs);
}