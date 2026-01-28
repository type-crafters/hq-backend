import { User, Mailer, VerificationToken, VerificationTokenRepository } from "@typecrafters/hq-domain";
import { GlobalExceptionHandler } from "@typecrafters/hq-error";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

const AWS_REGION = "us-east-1";
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));
/** @param {import("aws-lambda").APIGatewayProxyEventV2} event */
const handler = async (event) => {
    try {
        try {
            const body = JSON.parse(event.body);
            const user = User.fromCreateRequest(body);

            if (!user.email || !user.firstName) {
                return {
                    statusCode: 400,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        message: "Missing required fields."
                    })
                };
            }

            const mailer = new Mailer();
            mailer.setEnvironment(process.env);

            try {
                const token = VerificationToken.forEmailVerification(await mailer.sendVerificationEmail(user));
                const vTokenRepository = new VerificationTokenRepository(ddb);
                vTokenRepository.setEnvironment(process.env);
                await vTokenRepository.createVerificationToken(token);

                return {
                    statusCode: 200,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        message: "Invitation email sent to user."
                    })
                }
            } catch {
                return {
                    statusCode: 500,
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        message: "An error occurred while sending the confirmation email to the user."
                    })
                };
            }

        } catch {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Malformed request body."
                })
            };
        }
    } catch (error) {
        return GlobalExceptionHandler.forError(error);
    }
};

export default handler;