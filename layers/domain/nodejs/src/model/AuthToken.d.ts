export declare interface AuthTokenArgs {
    jti: string;
    exp: Date;
    iat: Date;
    sub: string;
    
}

export declare abstract class AuthToken {
    private static TOKEN_ISSUER: string;

    jti: string;
    exp: Date;
    iat: Date;
    iss: string;
    sub: string;
    typ: "access" | "refresh";

    protected constructor({
        jti,
        exp,
        iat,
        sub
    }: AuthTokenArgs);
}