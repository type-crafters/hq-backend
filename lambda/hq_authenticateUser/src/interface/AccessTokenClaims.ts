import type { UUID } from "crypto";

export interface AccessTokenClaims {
    jti: UUID;
    iat: number
    exp: number;
    sub: UUID;
    eml: string;
    prm: string[]
}