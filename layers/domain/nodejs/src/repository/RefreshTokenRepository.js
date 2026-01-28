import { createHmac } from "crypto";
import { ApplicationRepository } from "./ApplicationRepository";
import { DeleteCommand, GetCommand, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";

export class RefreshTokenRepository extends ApplicationRepository {
    constructor(documentClient) {
        super(documentClient);
        this.required = ["REFRESH_TOKEN_TABLE", "JTI_SECRET"];
    }

    #hashJti(jti) {
        return createHmac("sha256", this.getEnv("JTI_SECRET").asString())
            .update(jti)
            .digest("base64url");
    }

    async createRefreshToken(refreshToken) {
        this.checkEnvironment();

        try {
            await this.documentClient.send(new PutCommand({
                TableName: this.getEnv("REFRESH_TOKEN_TABLE").asString(),
                Item: {
                    ...refreshToken,
                    jti: this.#hashJti(refreshToken.jti)
                }
            }));

            return true;
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred uploading the refresh token to the database.", { cause: error });
        }
    }

    async existsByJti(jti) {
        this.checkEnvironment();
        try {
            const result = await this.documentClient.send(new GetCommand({
                TableName: this.getEnv("REFRESH_TOKEN_TABLE").asString(),
                Key: {
                    jti: this.#hashJti(jti)
                }
            }));

            return !!result.Item;
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred retrieving the refresh token from the database.", { cause: error });
        }
    }

    async revokeByJti(jti) {
        try {
            const result = await this.documentClient.send(new DeleteCommand({
                TableName: this.getEnv("REFRESH_TOKEN_TABLE").asString(),
                Key: {
                    jti: this.#hashJti(jti)
                },
                ReturnValues: "ALL_OLD"
            }));

            if (!result.Attributes || !Object.keys(result.Attributes).length) {
                return null;
            }

            return true;
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred revoking the refresh token on the database.", { cause: error });
        }
    }

    async revokeAllBySub(sub) {
        this.checkEnvironment();
        try {
            const tokens = await this.documentClient.send(new QueryCommand({
                TableName: this.getEnv("REFRESH_TOKEN_TABLE").asString(),
                IndexName: "sub-index",
                KeyConditionExpression: "#sub = :sub",
                ExpressionAttributeNames: {
                    "#sub": "sub"
                },
                ExpressionAttributeValues: {
                    ":sub": sub
                }
            }));

            if (!tokens.Items.length) {
                return 0;
            }

            const jtis = tokens.Items.map(token => token["jti"]).filter(jti => jti != null);

            let count = 0;

            for (const jti of jtis) {
                await this.documentClient.send(new DeleteCommand({
                    TableName: this.getEnv("REFRESH_TOKEN_TABLE").asString(),
                    Key: {
                        jti
                    }
                }));

                count++;
            }
            return count;
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred revoking the refresh token(s) on the database.", { cause: error });
        }
    }
}