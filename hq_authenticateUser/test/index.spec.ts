import assert from "node:assert";
import { beforeEach, describe, test, type TestContext } from "node:test";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import {
    DynamoDBDocumentClient,
    PutCommand,
    QueryCommand,
    type PutCommandOutput,
    type QueryCommandOutput
} from "@aws-sdk/lib-dynamodb";
import bcrypt from "bcrypt";
import { JSONResponse } from "@typecrafters/hq-types";

describe("hq_authenticateUser tests", async () => {
    let event: APIGatewayProxyEventV2;

    beforeEach((c) => {
        const ctx = c as TestContext;
        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                return {
                    $metadata: {},
                    Items: [{
                        id: "20230a09-2d5c-4a75-b4a1-689e6cbfeca3",
                        firstName: "Diego",
                        lastName: "Chan",
                        email: "name@example.com",
                        password: "$2b$10$I0T68IDq/f1Jss.1l./SHe2YCNdiTTFtNbeC4AXc0D/jdzQC1HM9C",
                        permissions: new Set(["create:user", "list:user", "update:user", "delete:user"]),
                        status: "active",
                        profilePictureUrl: "img/link-profile-picture.png",
                        preferredTheme: "dark"
                    }]
                } satisfies QueryCommandOutput;
            } else if (command instanceof PutCommand) {
                return {
                    $metadata: {}
                } satisfies PutCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            REFRESH_TOKEN_TABLE: "RefreshTokenTable",
            USER_TABLE: "UserTable",
            JTI_SECRET: "jti-secret-key",
            ACCESS_SECRET: "access-secret-key",
            REFRESH_SECRET: "refresh-secret-key"
        });

        ctx.mock.method(bcrypt, "compare", async (...args: any[]) => true);

        event = {
            version: "2.0",
            routeKey: "POST /auth/login",
            rawPath: "/auth/login",
            rawQueryString: "",
            cookies: [],
            headers: {
                "content-type": "application/json",
                "user-agent": "node:test",
                "host": "example.execute-api.us-east-1.amazonaws.com"
            },
            queryStringParameters: {},
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: {
                    method: "POST",
                    path: "/auth/login",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "POST /auth/login",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            body: JSON.stringify({
                email: "name@example.com",
                password: "password123",
                rememberMe: true
            }),
            pathParameters: {},
            isBase64Encoded: false,
            stageVariables: {}
        };
    });

    test("All in order", async (t) => {
        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.cookies && response.cookies.length);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        assert.ok(response.cookies.some(c => c.trim().startsWith("accessToken")));
        assert.ok(response.cookies.some(c => c.trim().startsWith("refreshToken")));
        const data = JSON.parse(response.body);
        assert.ok(data && data.item);
        assert.ok(Array.isArray(data.item));
    });

    test("APIGatewayProxyEventV2 has empty or missing body.", async (t) => {
        // Test setup
        delete event.body;

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has non-JSON parsable body.", async (t) => {
        // Test setup
        event.body = "{ invalid json }";

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 body is missing required fields", async (t) => {
        // Test setup
        event.body = JSON.stringify({ email: "name@example.com" });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("User with specified credentials does not exist", async (t) => {
        // Test setup
        event.body = JSON.stringify({
            email: "example@incorrect.net",
            password: "incorrectPassword456;",
            rememberMe: true
        });

        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                return {
                    $metadata: {},
                    Items: []
                } satisfies QueryCommandOutput;
            }
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("User provided an incorrect password", async (t) => {
        // Test setup
        event.body = JSON.stringify({
            email: "name@example.com",
            password: "incorrectPassword456;",
            rememberMe: true
        });

        t.mock.method(bcrypt, "compare", async (...args: any[]) => false);

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("DynamoDB lookup failed.", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                throw new Error("EVIL DynamoDB will not allow database lookups!!");
            }
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 500);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });
});