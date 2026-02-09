export interface AccessTokenClaims {
    iat: number;
    exp: number;
    iss: string;
    jti: string;
    sub: string;
    eml: string;
    rol: string[];
    typ: "access";
}