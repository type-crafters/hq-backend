import { createHmac } from "crypto";
import { ApplicationRepository } from "./ApplicationRepository";
import { DeleteCommand, GetCommand, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";

export class RefreshTokenRepository extends ApplicationRepository {
    constructor(documentClient) {
        super(documentClient);
        this._requiredEnvVars = ["REFRESH_TOKEN_TABLE", "JTI_SECRET"];
    }

    #hashJti(jti) {
        return createHmac("sha256", this._environment.get("JTI_SECRET"))
            .update(jti)
            .digest("base64url");
    }

    async createRefreshToken(refreshToken) {
        this._checkEnvionment();

        try {
            await this._documentClient.send(new PutCommand({
                TableName: this._environment.get("REFRESH_TOKEN_TABLE"),
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
        this._checkEnvionment();
        try {
            const result = await this._documentClient.send(new GetCommand({
                TableName: this._environment.get("REFRESH_TOKEN_TABLE"),
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
            const result = await this._documentClient.send(new DeleteCommand({
                TableName: this._environment.get("REFRESH_TOKEN_TABLE"),
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
        this._checkEnvionment();
        try {
            const tokens = await this._documentClient.send(new QueryCommand({
                TableName: this._environment.get("REFRESH_TOKEN_TABLE"),
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
                await this._documentClient.send(new DeleteCommand({
                    TableName: this._environment.get("REFRESH_TOKEN_TABLE"),
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