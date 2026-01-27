import type { RefreshToken } from "../model/RefreshToken";
import type { Nullable } from "../types";
import type { ApplicationRepository } from "./ApplicationRepository";
import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

export declare class RefreshTokenRepository extends ApplicationRepository {
    constructor(documentClient: DynamoDBDocumentClient);

    private hashJti(jti: string): string;

    public createRefreshToken(refreshToken: RefreshToken): Promise<true>;

    public existsByJti(jti: string): Promise<boolean>;

    public revokeByJti(jti: string): Promise<Nullable<true>>;

    public revokeAllBySub(sub: string): Promise<number>;
}