import { Mapper, Supplier } from "../types";
import { AuthToken } from "./AuthToken";

export declare interface AccessTokenArgs {
    jti: string;
    email: string;
    exp: Date;
    iat: Date;
    roles: string[];
    sub: string;
}

export declare interface AccessTokenJSONSchema {
    jti: string;
    email: string;
    exp: number;
    iat: number;
    iss: string;
    roles: string[];
    sub: string;
    typ: "access";
}

export declare interface AccessTokenClaims {
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

    public toJSON: Supplier<AccessTokenJSONSchema>;

    public static fromClaims: Mapper<AccessTokenClaims, AccessToken>;

    constructor({
        jti,
        email,
        exp,
        iat,
        roles,
        sub,
    }: AccessTokenArgs);
}