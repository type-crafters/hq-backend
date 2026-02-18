import type { UUID } from "crypto";

export interface RefreshTokenClaims {
    jti: UUID;
    iat: number
    exp: number;
    sub: UUID;
}