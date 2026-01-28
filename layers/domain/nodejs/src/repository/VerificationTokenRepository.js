import { RepositoryError } from "../error/RepositoryError";
import { ApplicationRepository } from "./ApplicationRepository";

export class VerificationTokenRepository extends ApplicationRepository {
    constructor(documentClient) {
        super(documentClient);
        this.required = ["VERIFICATION_TOKEN_TABLE"];
    }

    async createVerificationToken(verificationToken) {
        this.checkEnvironment();
        try {
            await this.documentClient.send(new PutCommand({
                TableName: this.getEnv("VERIFICATION_TOKEN_TABLE").asString(),
                Item: verificationToken.toItem()
            }));

            return true;
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred uploading the user to the database.", { cause: error });
        }
    }
}