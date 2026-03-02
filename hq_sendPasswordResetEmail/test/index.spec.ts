/// <reference types="node" />
import { describe, test, beforeEach, type TestContext } from "node:test";
import assert from "node:assert";
import { mock } from "node:test";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { type JSONResponse } from "@typecrafters/hq-types";
import { EJS, Mailer } from "@typecrafters/hq-lib";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

describe("hq_sendPasswordResetEmail tests", () => {
    let event: APIGatewayProxyEventV2;
    let rfs: (...args: any) => string;

    mock.module("fs", {
        namedExports: {
            readFileSync: (...args: any) => rfs(args)
        }
    });

    beforeEach((c) => {
        const ctx = c as TestContext;

        rfs = (...args: any) => "text";

        ctx.mock.method(EJS.prototype, "using", (...args: any[]) => (
            "<!DOCTYPE html>\n<html>\n<h1>Reset Password</h1>\n</html>"
        ));

        ctx.mock.method(Mailer.prototype, "sendHTMLEmail", async (...args: any[]) => ({
            accepted: ["name@example.com"],
            rejected: [],
            pending: [],
            response: "250 Message queued",
            messageId: "<abc123@example.com>"
        }));

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => ({
            Items: [{
                id: "user-123",
                firstName: "John",
                email: "name@example.com"
            }]
        }));

        ctx.mock.property(process, "env", {
            PAGE_URL: "http://localhost:5173/",
            VERIFICATION_TOKEN_TABLE: "VerificationTokenTable",
            USER_TABLE: "UserTable",
            SMTP_USER: "example@domain.com",
            SMTP_PASS: "password123"
        });

        event = {
            version: "2.0",
            routeKey: "POST /auth/send-password-reset",
            rawPath: "/auth/send-password-reset",
            rawQueryString: "",
            headers: {
                "content-type": "application/json",
                "user-agent": "node:test",
                "host": "example.execute-api.us-east-1.amazonaws.com"
            },
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: {
                    method: "POST",
                    path: "/auth/send-password-reset",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "POST /auth/send-password-reset",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            body: JSON.stringify({ email: "name@example.com" }),
            isBase64Encoded: false
        };
    });

    test("All in order", async (t) => {
        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has empty or missing body", async (t) => {
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

    test("APIGatewayProxyEventV2 has non-JSON parsable body", async (t) => {
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

    test("APIGatewayProxyEventV2 body is missing required email field", async (t) => {
        // Test setup
        event.body = JSON.stringify({});

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

    test("APIGatewayProxyEventV2 body has empty email field", async (t) => {
        // Test setup
        event.body = JSON.stringify({ email: "" });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("User with provided email does not exist", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => ({
            Items: []
        }));

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
    });

    test("DynamoDBDocumentClient class throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            throw new Error("EVIL DynamoDB errors out on send commands!!");
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 500);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Mailer sendHTMLEmail throws error", async (t) => {
        // Test setup
        t.mock.method(Mailer.prototype, "sendHTMLEmail", async (...args: any[]) => {
            throw new Error("EVIL mailer will not send your reset links!!");
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 500);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });
});