import bcrypt from "bcrypt";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { User, UserRepository } from "@typecrafters/hq-domain"
import { GlobalExceptionHandler } from "@typecrafters/hq-error";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: "us-east-1" }));

/** @param {import("aws-lambda").APIGatewayProxyEventV2} event */
const handler = async (event) => {
    const admin = {
        sub: "12345",
        email: "name@example.com",
        roles: new Set(["create:user"])
    };  // TODO obtain from auth token 

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
        if (admin) {
            if (admin.roles.has("create:user")) {
                const user = User.fromCreateRequest(body);
                user.password = await bcrypt.hash(user.password, 10);

                const userRepository = new UserRepository(ddb);
                userRepository.setEnvironment(process.env);

                await userRepository.createUser(user);

                return {
                    statusCode: 201,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        message: "User created successfully"
                    })
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
                };
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
            };
        }
    } catch (error) {
        return GlobalExceptionHandler.forError(error);
    }
};

export default handler;