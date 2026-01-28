import { DeleteCommand, GetCommand, PutCommand, QueryCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { ApplicationRepository } from "./ApplicationRepository";
import { RepositoryError } from "../error/RepositoryError";
import { User } from "../model/User";

export class UserRepository extends ApplicationRepository {
    constructor(documentClient) {
        super(documentClient);
        this.required = ["USER_TABLE"];
    }

    async createUser(user) {
        this.checkEnvironment();
        try {
            await this.documentClient.send(new PutCommand({
                TableName: this.getEnv("USER_TABLE").asString(),
                Item: {...user}
            }));

            return user;
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred uploading the user to the database.", { cause: error });
        }
    }

    async getById(id) {
        this.checkEnvironment();
        try {
            const result = await this.documentClient.send(new GetCommand({
                TableName: this.getEnv("USER_TABLE").asString(),
                Key: {
                    id
                }
            }));

            if (!result.Item || !Object.keys(result.Item).length) {
                return null;
            }

            return User.fromItem(result.Item);
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred retrieving the user from the database.", { cause: error });
        }
    }

    async getByEmail(email) {
        this.checkEnvironment();
        try {
            const result = await this.documentClient.send(new QueryCommand({
                TableName: this.getEnv("USER_TABLE").asString(),
                IndexName: "email-index",
                KeyConditionExpression: "#email = :email",
                ExpressionAttributeNames: {
                    "#email": "email"
                },
                ExpressionAttributeValues: {
                    ":email": email.toLowerCase()
                }
            }));

            if (!result.Items.length || !Object.keys(result.Items[0]).length) {
                return null;
            }

            return User.fromItem(result.Items[0]);
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred retrieving the user from the database.", { cause: error });
        }
    }

    async deleteById(id) {
        this.checkEnvironment();
        try {
            const result = await this.documentClient.send(new DeleteCommand({
                TableName: this.getEnv("USER_TABLE").asString(),
                Key: {
                    id
                },
                ReturnValues: "ALL_OLD"
            }));

            if (!result.Attributes || !Object.keys(result.Attributes).length) {
                return null;
            }

            return User.fromItem(result.Attributes);
        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred deleting the user from the database.", { cause: error });
        }
    }

    async updateUser(user) {
        this.checkEnvironment();
        try {
            const item = Object.fromEntries(Object.entries({ ...user }).filter(([_, value]) => value != null));

            const id = item.id;
            delete item.id;

            if (Object.keys(item).length) {
                const updates = []
                const ExpressionAttributeNames = {};
                const ExpressionAttributeValues = {};

                Object.entries(item).forEach(([key, value]) => {
                    updates.push(`#${key} = :${key}`);
                    ExpressionAttributeNames[`#${key}`] = key;
                    ExpressionAttributeValues[`:${key}`] = value;
                });

                const UpdateExpression = `SET ${updates.join(", ")}`;

                try {
                    await this.documentClient.send(new UpdateCommand({
                        TableName: this.getEnv("USER_TABLE").asString(),
                        Key: {
                            id
                        },
                        UpdateExpression,
                        ExpressionAttributeNames,
                        ExpressionAttributeValues,
                        ReturnValues: "ALL_NEW",
                        ConditionExpression: "attribute_exists(id)"
                    }));
                } catch (error) {
                    if (error instanceof ConditionalCheckFailedException) {
                        return null;
                    }
                    throw error;
                }

                if (!result.Attributes || !Object.keys(result.Attributes).length) {
                    return null;
                }

                return User.fromItem(result.Attributes);
            }

            throw new RepositoryError("Provided user does not contain any updatable values.");

        } catch (error) {
            if (error instanceof RepositoryError) throw error;
            throw new RepositoryError("An error occurred updating the user on the database.", { cause: error });
        }
    }
}