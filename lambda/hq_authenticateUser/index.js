import assert from "assert";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { GlobalExceptionHandler } from "@typecrafters/hq-error";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DeleteCommand, DynamoDBDocumentClient, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { AccessToken, Cookie, RefreshToken } from "@typecrafters/hq-entity";
import { randomUUID } from "crypto";
import { UserRepository } from "@typecrafters/hq-domain";

const USER_TABLE = process.env.USER_TABLE;
const REFRESH_TABLE = process.env.REFRESH_TABLE;
const ACCESS_SECRET = process.env.ACCESS_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const TOKEN_ISSUER = "org.typecrafters";
const ACCESS_EXPIRY = 15 * 60; // 15m
const REFRESH_EXPIRY = 7 * 86400; // 7d

assert.ok(USER_TABLE, "Required environment variable USER_TABLE not set.");
assert.ok(REFRESH_TABLE, "Required environment variable REFRESH_TABLE not set.");
assert.ok(ACCESS_SECRET, "Required environment variable ACCESS_SECRET not set.");
assert.ok(REFRESH_SECRET, "Required environment variable REFRESH_SECRET not set.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: "us-east-1" }))

/** @param {import("aws-lambda").APIGatewayProxyEventV2} event */
const handler = async (event) => {
    try {

        const body = JSON.parse(event.body);

        if (!body || !Object.keys(body).length) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Missing request body"
                })
            };
        }

        const { email, password } = body;

        if (!email || !password) {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Missing required fields"
                })
            };
        }

        const userRepository = new UserRepository(ddb);
        userRepository.setEnvironment(process.env);

        const user = await userRepository.getByEmail(email);

        if (user === null) {
            return {
                statusCode: 404,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "User not found"
                })
            };
        }

        if (!(await bcrypt.compare(password, user.password))) {
            return {
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Invalid credentials"
                })
            }
        }

        /** TODO create refresh token repository */
        const existingTokens = (await ddb.send(new QueryCommand({
            TableName: REFRESH_TABLE,
            IndexName: "sub-index",
            KeyConditionExpression: "#sub = :sub",
            ExpressionAttributeNames: {
                "#sub": "sub"
            },
            ExpressionAttributeValues: {
                ":sub": user.id
            }
        }))).Items;

        if (existingTokens) {
            await Promise.all(
                existingTokens.map(t => {
                    const token = new RefreshToken(...t);
                    return ddb.send(
                        new DeleteCommand({
                            TableName: REFRESH_TABLE,
                            Key: {
                                jti: token.jti
                            }
                        })
                    );
                })
            );
        }

        const accessToken = new AccessToken({
            jti: randomUUID(),
            iss: TOKEN_ISSUER,
            iat: Date.now(),
            exp: Date.now() + (ACCESS_EXPIRY * 1000),
            ...user.mapper().toClaims() // { sub, email, roles }
        });

        const signedAccessToken = jwt.sign(accessToken.mapper().toToken(), ACCESS_SECRET);

        const refreshToken = new RefreshToken({
            jti: randomUUID(),
            iss: TOKEN_ISSUER,
            iat: Date.now(),
            exp: Date.now() + (REFRESH_EXPIRY * 1000),
            sub: user.id
        });

        const signedRefreshToken = jwt.sign(refreshToken.mapper().toToken(), REFRESH_SECRET);

        const cookies = [
            Cookie.builder()
                .name("accessToken")
                .value(accessToken)
                .maxAge(ACCESS_EXPIRY)
                .path("/")
                .sameSite("None")
                .httpOnly(true)
                .secure(true)
                .build()
                .toString(),
            Cookie.builder()
                .name("refreshToken")
                .value(refreshToken)
                .maxAge(REFRESH_EXPIRY)
                .path("/")
                .sameSite("None")
                .httpOnly(true)
                .secure(true)
                .build()
                .toString()
        ];

        return {
            statusCode: 200,
            headers: {
                "Content-Type": "application/json"
            },
            cookies
        }
    } catch (error) {
        return GlobalExceptionHandler.forError(error);
    }
};

export default handler;