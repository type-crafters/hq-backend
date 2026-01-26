import { GlobalExceptionHandler } from "@typecrafters/hq-entity";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb"
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { UserRepository } from "@typecrafters/hq-domain"

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: "us-east-1" }));

/** @param {import("aws-lambda").APIGatewayProxyEventV2} event */
const handler = async (event) => {
    const admin = {
        sub: "12345",
        email: "name@example.com",
        roles: new Set(["delete:user"])
    }; // TODO obtain from auth token

    try {
        const userId = event.pathParameters?.["id"];
        if (!userId) {
            return {
                statusCode: 400,
                body: JSON.stringify({
                    message: "Missing {id} parameter"
                })
            };
        }
        if (admin) {
            if (admin.roles.has("delete:user")) {
                const userRepository = new UserRepository(ddb);
                userRepository.setEnvironment(process.env);

                const user = await userRepository.deleteById(userId);

                if (user === null) {
                    return {
                        statusCode: 404,
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({
                            message: "User not found"
                        })
                    }
                } else {
                    return {
                        statusCode: 204
                    }
                }
            } else {
                return {
                    statusCode: 403,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        message: "Missing required permissions"
                    })
                }
            }
        } else {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Unrecognized user"
                })
            }
        }
    } catch (error) {
        return GlobalExceptionHandler.forError(error);
    }
};

export default handler;