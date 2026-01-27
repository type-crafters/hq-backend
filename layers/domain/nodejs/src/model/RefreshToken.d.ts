import { Mapper, Supplier } from "../types";
import { AuthToken } from "./AuthToken";

export declare interface RefreshTokenArgs {
    jti: string;
    exp: Date;
    iat: Date;
    sub: string;
}

export declare interface RefreshTokenJSONSchema {
    jti: string;
    exp: number;
    iat: number;
    iss: string;
    sub: string;
    typ: "refresh";
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

    public toJSON: Supplier<RefreshTokenJSONSchema>;

    public static fromClaims: Mapper<RefreshTokenClaims, RefreshToken>;
}
