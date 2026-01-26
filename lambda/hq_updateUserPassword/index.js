import bcrypt from "bcrypt";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { GlobalExceptionHandler } from "@typecrafters/hq-error";
import { UserRepository } from "@typecrafters/hq-domain";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: "us-east-1" }));

/** @param {import("aws-lambda").APIGatewayProxyEventV2} event */
const handler = async (event) => {
    const admin = {
        sub: "12345",
        email: "name@example.com",
        roles: new Set()
    }; // TODO obtain from auth token

    try {
        const body = JSON.parse(event.body);
        if (!body || !Object.keys(body).length) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Missing request body."
                })
            }
        }

        const { newPassword, confirmNewPassword } = body;

        if (!newPassword || !confirmNewPassword) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Missing required fields"
                })
            }
        }

        if (newPassword !== confirmNewPassword) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Passwords do not match"
                })
            }
        }

        if (admin) {
            const userRepository = new UserRepository(ddb);
            userRepository.setEnvironment(process.env);

            const partial = {
                id: admin.sub,
                password: await bcrypt.hash(newPassword, 10),
                firstTimePassword: false
            };

            const result = await userRepository.updateUser(partial);

            if (result === null) {
                return {
                    statusCode: 404,
                    body: JSON.stringify({
                        message: "User not found."
                    })
                };
            } else {
                return {
                    statusCode: 204
                };
            }
        } else {
            return {
                statusCode: 401,
                body: JSON.stringify({
                    message: "Unrecognized user"
                })
            };
        }
    } catch (error) {
        return GlobalExceptionHandler.forError(error);
    }
};

export default handler;