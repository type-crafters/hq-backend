import { RefreshToken } from "../model/RefreshToken";
import { ApplicationRepository } from "./ApplicationRepository";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

export class RefreshTokenRepository extends ApplicationRepository {
    constructor(documentClient: DynamoDBDocumentClient);

    private hashJti(jti: string): string;

    public createRefreshToken(refreshToken: RefreshToken): Promise<true>;

    public existsByJti(jti: string): Promise<boolean>

    public revokeByJti(jti: string): Promise<true | null>;

    public revokeAllBySub(sub: string): number;
}