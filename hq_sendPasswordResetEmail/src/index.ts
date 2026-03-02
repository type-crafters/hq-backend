import path from "path";
import { readFileSync } from "fs";
import { createHash, randomBytes } from "node:crypto";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { VerificationTokenType, type JSONResponse, type SendPasswordResetEmailRequest, type UserItem, type VerificationTokenItem } from "@typecrafters/hq-types";
import { HttpResponse, HttpCode, LoggerFactory, type ResponseObject, EJS, Mailer } from "@typecrafters/hq-lib";
import { BatchWriteCommand, DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";

const region = "us-east-1";
const MIN = 60_000;
const USER_TABLE = process.env.USER_TABLE;
const VERIFICATION_TOKEN_TABLE = process.env.VERIFICATION_TOKEN_TABLE;
const PAGE_URL = process.env.PAGE_URL;

const template: string = readFileSync(
    path.resolve(import.meta.dirname, "template", "reset-password.ejs"),
    { encoding: "utf-8" }
);

if (!USER_TABLE) throw new Error("Missing required environment variable 'USER_TABLE'.");
if (!VERIFICATION_TOKEN_TABLE) throw new Error("Missing required environment variable 'VERIFICATION_TOKEN_TABLE'.");
if (!PAGE_URL) throw new Error("Missing required environment variable 'PAGE_URL'.");
if (!process.env.SMTP_USER) throw new Error("Missing required environment variable 'SMTP_USER'.");
if (!process.env.SMTP_PASS) throw new Error("Missing required environment variable 'SMTP_PASS'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body } = event;

        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty request body."
                } satisfies JSONResponse)
                .build();
        }

        let data;

        try {
            data = JSON.parse(body);
        } catch (error) {
            if (error instanceof SyntaxError) {
                return HttpResponse.builder()
                    .status(HttpCode.BadRequest)
                    .json({
                        success: false,
                        message: "Malformed request body."
                    } satisfies JSONResponse)
                    .build();
            }
            throw error;
        }

        const { email }: SendPasswordResetEmailRequest = data;

        if (typeof email !== "string" || !email) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty required fields."
                } satisfies JSONResponse)
                .build();
        }

        const result = await ddb.send(new QueryCommand({
            TableName: USER_TABLE,
            IndexName: "email-index",
            KeyConditionExpression: "#email = :email",
            ExpressionAttributeNames: { "#email": "email" },
            ExpressionAttributeValues: { ":email": email.trim().toLowerCase() },
            Limit: 1
        }));

        if (!result || !result.Items || !result.Items.length) {
            return HttpResponse.builder()
                .status(HttpCode.OK)
                .json({
                    success: true,
                    message: "If an account with this email exists, a reset link was sent."
                } satisfies JSONResponse)
                .build();
        }

        const { id, firstName } = result.Items[0] as UserItem;

        const now = Date.now();
        const url = new URL("/auth/reset-password", PAGE_URL);
        const verificationToken = randomBytes(32).toString("base64url");
        url.searchParams.append("token", verificationToken);
        url.searchParams.append("sub", id)

        const tokenHash = createHash("sha256")
            .update(verificationToken)
            .digest("hex");

        const existing = await ddb.send(new QueryCommand({
            TableName: VERIFICATION_TOKEN_TABLE,
            IndexName: "sub-type-index",
            KeyConditionExpression: "#sub = :sub AND #type = :type",
            ExpressionAttributeNames: {
                "#sub": "sub",
                "#type": "type"
            },
            ExpressionAttributeValues: {
                ":sub": id,
                ":type": VerificationTokenType.PasswordReset
            },
            ProjectionExpression: "token"
        }));

        await ddb.send(new BatchWriteCommand({
            RequestItems: {
                [VERIFICATION_TOKEN_TABLE]: [
                    ...(existing.Items ?? []).map(t => ({
                        DeleteRequest: {
                            Key: { token: t.token }
                        }
                    })),
                    {
                        PutRequest: {
                            Item: {
                                token: tokenHash,
                                sub: id,
                                type: VerificationTokenType.PasswordReset,
                                createdAt: now,
                                expiresAt: Math.floor((now + 15*MIN) / 1000)
                            } satisfies VerificationTokenItem
                        }
                    }
                ]
            }
        }));

        const text: string = [
            `Hello ${firstName},`,
            "We received a request to reset the password for your TypeCrafters account. " +
            "Please confirm your email address and continue the process by clicking the link below.",
            "",
            url.toString(),
            "",
            "This link will expire in 15 minutes for security reasons. If you did not request a password reset, " +
            "you can safely ignore this email. Your account will remain secure.",
            "",
            "Thanks,",
            "- The team at TypeCrafters"
        ].join("\n");

        const html = EJS.render(template).using({ firstName, url: url.toString() });
        const mailer = new Mailer(process.env);
        await mailer.sendHTMLEmail({
            to: email,
            subject: "Your password reset request",
            html,
            text
        });

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .json({
                success: true,
                message: "If an account with this email exists, a reset link was sent."
            } satisfies JSONResponse)
            .build();
    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .json({
                success: false,
                message: "A server-side error occurred."
            } satisfies JSONResponse)
            .build();
    }
};

export { handler };