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

export declare interface RefreshTokenClaims {
    exp: Date;
    iat: Date;
    sub: string;
}


export declare class RefreshToken extends AuthToken {
    constructor({
        jti,
        exp,
        iat,
        sub
    }: RefreshTokenArgs);

    public toItem(): RefreshTokenItem;

    public static fromClaims(claims: RefreshTokenClaims): RefreshToken;
}
