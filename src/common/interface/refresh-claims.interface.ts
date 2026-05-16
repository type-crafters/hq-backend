import type { AccessClaims } from "@/common/interface/access-claims.interface";

export interface RefreshClaims extends AccessClaims {
    jti?: string;
    exp?: number;
    iat?: number;
}