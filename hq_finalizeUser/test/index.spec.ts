/// <reference types="node" />
import { TransactionCanceledException } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, TransactWriteCommand, TransactWriteCommandOutput } from "@aws-sdk/lib-dynamodb";
import { JSONResponse } from "@typecrafters/hq-types";
import assert from "assert";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { beforeEach, describe, test, type TestContext } from "node:test";
import bcrypt from "bcrypt";

describe("hq_finalizeUser tests", () => {
    let event: APIGatewayProxyEventV2;
    beforeEach((c) => {
        const ctx = c as TestContext;
        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof TransactWriteCommand) {
                return {
                    $metadata: {}
                } satisfies TransactWriteCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            USER_TABLE: "UserTable",
            VERIFICATION_TOKEN_TABLE: "VerificationTokenTable"
        });

        ctx.mock.method(bcrypt, "hash", async (...args: any[]) => "$2b$10$hashedPassword");

        event = {
            version: "2.0",
            routeKey: "POST /users/confirm",
            rawPath: "/users/confirm",
            rawQueryString: "token=GomTlMmvfS8JAI9W_n0USLLBk0Y2f1xbqTgVXdmJCeo&sub=814bfd71-21f4-4dd8-b7c7-b4bbdf0a98e7",
            cookies: [],
            headers: {
                "content-type": "application/json"
            },
            queryStringParameters: {
                token: "GomTlMmvfS8JAI9W_n0USLLBk0Y2f1xbqTgVXdmJCeo",
                sub: "814bfd71-21f4-4dd8-b7c7-b4bbdf0a98e7"
            },
            requestContext: {
                accountId: "12345678",
                apiId: "hq-api",
                domainName: "",
                domainPrefix: "",
                http: {
                    method: "POST",
                    path: "/users/confirm",
                    protocol: "HTTP 1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12345678",
                routeKey: "POST /users/confirm",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now(),
            },
            body: JSON.stringify({
                password: "Password123;",
                confirmPassword: "Password123;"
            }),
            pathParameters: undefined,
            isBase64Encoded: false,
            stageVariables: undefined
        }
    });

    test("All in order", async (t) => {
        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has a missing or empty querystring", async (t) => {
        // Test setup
        event.rawQueryString = "";
        delete event.queryStringParameters;

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 is missing required querystring parameters", async (t) => {
        // Test setup
        event.queryStringParameters = {
            sub: "814bfd71-21f4-4dd8-b7c7-b4bbdf0a98e7"
        };

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has a missing or empty body", async (t) => {
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
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has a malformed body", async (t) => {
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
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Event body is missing required fields", async (t) => {
        // Test setup
        event.body = JSON.stringify({
            confirmPassword: "Password123;"
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Provided password is weak", async (t) => {
        // Test setup
        event.body = JSON.stringify({
            password: "hello",
            confirmPassword: "hello"
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Passwords do not match", async (t) => {
        // Test setup
        event.body = JSON.stringify({
            password: "Password123;",
            confirmPassword: "Pass_word_456"
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("An error occurs in the DynamoDB transaction.", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof TransactWriteCommand) {
                throw new TransactionCanceledException({
                    $metadata: {},
                    message: "EVIL DynamoDB is not ACID!!"
                });
            }
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 404);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("DynamoDBDocumentClient class fails", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            throw new Error("EVIL DynamoDB will not update your users!!");
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
        assert.ok(!body.success);
        assert.ok(body.message);
    });
});