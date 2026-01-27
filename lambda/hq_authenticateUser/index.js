import assert from "assert";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { GlobalExceptionHandler } from "@typecrafters/hq-error";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { AccessToken, Cookie, UserRepository, RefreshToken, RefreshTokenRepository } from "@typecrafters/hq-domain";

const ACCESS_SECRET = process.env.ACCESS_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const ACCESS_EXPIRY = 15 * 60; // 15m
const REFRESH_EXPIRY = 7 * 86400; // 7d

assert(ACCESS_SECRET, "Required environment variable ACCESS_SECRET not set.");
assert(REFRESH_SECRET, "Required environment variable REFRESH_SECRET not set.");

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({ region: "us-east-1" }));

/** @param {import("aws-lambda").APIGatewayProxyEventV2} event */
const handler = async (event) => {
    try {
        let body;
        try {
            body = JSON.parse(event.body);
        } catch {
            return {
                statusCode: 400,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Malformed JSON body"
                })
            }
        }

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
                statusCode: 401,
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    message: "Invalid credentials"
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
            };
        }

        const refreshTokenRepository = new RefreshTokenRepository(ddb);
        refreshTokenRepository.setEnvironment(process.env);

        await refreshTokenRepository.revokeAllBySub(user.id);

        const accessToken = AccessToken.fromClaims({
            iat: new Date(),
            exp: new Date(Date.now() + (ACCESS_EXPIRY * 1000)),
            ...user.getClaims() // { sub, email, roles }
        });

        const refreshToken = RefreshToken.fromClaims({
            iat: new Date(),
            exp: new Date(Date.now() + (REFRESH_EXPIRY * 1000)),
            sub: user.id
        });

        const signedAccessToken = jwt.sign(accessToken.toJSON(), ACCESS_SECRET);
        const signedRefreshToken = jwt.sign(refreshToken.toJSON(), REFRESH_SECRET);
        
        await refreshTokenRepository.createRefreshToken(refreshToken);

        const cookies = [
            Cookie.builder()
                .name("accessToken")
                .value(signedAccessToken)
                .maxAge(ACCESS_EXPIRY)
                .path("/")
                .sameSite("None")
                .httpOnly(true)
                .secure(true)
                .build()
                .toString(),
            Cookie.builder()
                .name("refreshToken")
                .value(signedRefreshToken)
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
            cookies,
            body: JSON.stringify({
                message: "Authentication successful"
            })
        };
    } catch (error) {
        return GlobalExceptionHandler.forError(error);
    }
};

export default handler;