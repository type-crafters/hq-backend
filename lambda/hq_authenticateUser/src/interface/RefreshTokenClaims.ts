export interface RefreshTokenClaims {
    iat: number;
    exp: number;
    iss: string;
    jti: string;
    sub: string;
    typ: "refresh";
}