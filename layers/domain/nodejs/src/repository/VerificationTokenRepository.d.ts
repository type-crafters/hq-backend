import type { VerificationToken } from "../model/VerificationToken";
import type { ApplicationRepository } from "./ApplicationRepository";

export declare class VerificationTokenRepository extends ApplicationRepository {
    constructor(documentClient: DynamoDBDocumentClient);

    public createVerificationToken(verificationToken: VerificationToken): Promise<true>;
}