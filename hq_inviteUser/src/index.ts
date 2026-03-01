import type { APIGatewayProxyEventV2 } from "aws-lambda";
import {
    HttpResponse,
    HttpCode,
    LoggerFactory,
    type ResponseObject,
    Mailer,
    EJS,
    Authenticator,
    ExpiredTokenError,
    InvalidTokenError,
    Cookie
} from "@typecrafters/hq-lib";
import {
    ColorScheme,
    UserStatus,
    VerificationTokenType,
    type InviteUserRequest,
    type JSONResponse,
    type UserItem,
    type VerificationTokenItem
} from "@typecrafters/hq-types";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { createHash, randomBytes, randomUUID } from "crypto";
import { readFileSync } from "fs";
import path from "path";

const DAY = 86_400_000;

const region = "us-east-1";
const PAGE_URL = process.env.PAGE_URL;
const USER_TABLE = process.env.USER_TABLE;
const VERIFICATION_TOKEN_TABLE = process.env.VERIFICATION_TOKEN_TABLE;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;

const template: string = readFileSync(
    path.resolve(import.meta.dirname, "template", "verify-email.ejs"),
    { encoding: "utf-8" }
);

if (!PAGE_URL) throw new Error("Missing required environment variable 'PAGE_URL'.");
if (!USER_TABLE) throw new Error("Missing required environment variable 'USER_TABLE'.");
if (!VERIFICATION_TOKEN_TABLE) throw new Error("Missing required environment variable 'VERIFICATION_TOKEN_TABLE'.");
if (!SMTP_USER) throw new Error("Missing required environment variable 'SMTP_USER'.");
if (!SMTP_PASS) throw new Error("Missing required environment variable 'SMTP_PASS'.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region }));

const handler = async (event: APIGatewayProxyEventV2): Promise<ResponseObject> => {
    const logger = LoggerFactory.forFunction(handler);
    try {
        const { body, cookies } = event;

        if (!cookies) {
            logger.error("No cookies sent in request. User is not authorized to use this endpoint.");
            return HttpResponse.builder()
                .status(HttpCode.Unauthorized)
                .json({
                    success: false,
                    message: "Unauthorized."
                })
                .build();
        }

        try {
            const cookielist = cookies.map(c => Cookie.from(c));
            const accessToken = cookielist.find(c => c.name === "accessToken");

            if (!accessToken) {
                logger.error("No token cookie to read. User is not authorized to use this endpoint.");
                return HttpResponse.builder()
                    .status(HttpCode.Unauthorized)
                    .json({
                        success: false,
                        message: "Unauthorized."
                    } satisfies JSONResponse)
                    .build();
            }

            const permissions = Authenticator.access(process.env).getPermissions(accessToken.value);

            if (!permissions.includes("create:user")) {
                return HttpResponse.builder()
                    .status(HttpCode.Forbidden)
                    .json({
                        success: false,
                        message: "User not authorized to perform this action."
                    } satisfies JSONResponse)
                    .build();
            }
        } catch (error) {
            const response = HttpResponse.builder()
                .status(HttpCode.Unauthorized)
                .json({
                    success: false,
                    message: "Unauthorized."
                } satisfies JSONResponse)
                .build();
            if (error instanceof TypeError) {
                logger.error("One or more request cookies was malformed.");
                return response;
            } else if (error instanceof ExpiredTokenError) {
                logger.error("Token expired.");
                return response;
            } else if (error instanceof InvalidTokenError) {
                logger.error("Invalid token.");
                return response;
            }
            throw error;
        }

        if (!body) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or empty request body."
                } satisfies JSONResponse)
                .build();
        }

        let data: InviteUserRequest;

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

        const { firstName, lastName, email, permissions } = data;

        if (
            !firstName || typeof firstName !== "string"
            ||
            !lastName || typeof lastName !== "string"
            ||
            !email || typeof email !== "string"
            ||
            !permissions || !Array.isArray(permissions)
        ) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "Missing or invalid required fields."
                } satisfies JSONResponse)
                .build();
        }

        const result = await ddb.send(new QueryCommand({
            TableName: USER_TABLE,
            IndexName: "email-index",
            Select: "COUNT",
            KeyConditionExpression: "#email = :email",
            ExpressionAttributeNames: { "#email": "email" },
            ExpressionAttributeValues: { ":email": "email" },
            Limit: 1
        }));

        if (result.Count) {
            return HttpResponse.builder()
                .status(HttpCode.BadRequest)
                .json({
                    success: false,
                    message: "User with this email already exists."
                } satisfies JSONResponse)
                .build();
        }

        const id = randomUUID();
        const now: number = Date.now();
        const verificationToken: string = randomBytes(32).toString("base64url");

        const url = new URL("/users/confirm", PAGE_URL);
        url.searchParams.append("token", verificationToken);
        url.searchParams.append("sub", id);

        const tokenHash = createHash("sha256")
            .update(verificationToken)
            .digest("hex");

        await ddb.send(new PutCommand({
            TableName: USER_TABLE,
            Item: {
                id,
                firstName,
                lastName,
                email: email.trim().toLowerCase(),
                permissions: new Set(permissions),
                status: UserStatus.Unverified,
                preferredTheme: ColorScheme.Light,
                createdAt: now,
                lastUpdatedAt: now
            } satisfies Partial<UserItem>
        }));

        await ddb.send(new PutCommand({
            TableName: VERIFICATION_TOKEN_TABLE,
            Item: {
                token: tokenHash,
                sub: id,
                type: VerificationTokenType.EmailConfirmation,
                createdAt: now,
                expiresAt: Math.floor((now + 1 * DAY) / 1000)
            } satisfies VerificationTokenItem
        }));

        const text: string = [
            `Hello ${firstName},`,
            "You have been invited to join TypeCrafters HQ as an administrator." +
            "Please confirm your email address by clicking the link below.",
            "",
            url.toString(),
            "",
            "Once in the application, you'll be asked to create a password for your account. " +
            "This invitation link will expire in 24 hours. If you were not expecting this " +
            "invitation, you can safely ignore this email.",
            "",
            "Thanks,",
            "- The team at TypeCrafters"

        ].join("\n");
        const html = EJS.render(template).using({ firstName, url: url.toString() });
        const mailer = new Mailer(process.env);
        await mailer.sendHTMLEmail({
            to: email,
            subject: "Please verify your email address",
            html,
            text
        });

        return HttpResponse.builder()
            .status(HttpCode.OK)
            .json({
                success: true,
                message: "User invitation sent."
            } satisfies JSONResponse)
            .build();
    } catch (error) {
        logger.error(error);
        return HttpResponse.builder()
            .status(HttpCode.InternalServerError)
            .json({
                success: false,
                message: "A server-side error occured."
            } satisfies JSONResponse)
            .build();
    }
};

export { handler };