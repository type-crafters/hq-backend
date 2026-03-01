/// <reference types="node"/>
import assert from "node:assert"
import { describe, test, beforeEach, type TestContext, mock } from "node:test";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { Authenticator, EJS, InvalidTokenError, Mailer } from "@typecrafters/hq-lib";
import { DynamoDBDocumentClient, PutCommand, PutCommandOutput, QueryCommand, QueryCommandOutput } from "@aws-sdk/lib-dynamodb";
import { JSONResponse } from "@typecrafters/hq-types";

describe("hq_inviteUser tests", () => {
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

        ctx.mock.method(EJS.prototype, "using", (data: any) => "<!DOCTYPE html>\n<html>\n<h1>Hello World!</h1>\n</html>");

        ctx.mock.method(Mailer.prototype, "sendHTMLEmail", async (...args: any[]) => ({
            accepted: ["name@example.com"],
            rejected: [],
            pending: [],
            response: "250 Message queued",
            messageId: "<abc123@example.com>"
        }));

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                return {
                    $metadata: {},
                    Count: 0
                } satisfies QueryCommandOutput;
            } else if (command instanceof PutCommand) {
                return {
                    $metadata: {}
                } satisfies PutCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            PAGE_URL: "http://localhost:5173/",
            VERIFICATION_TOKEN_TABLE: "VerificationTokenTable",
            USER_TABLE: "UserTable",
            SMTP_SERVICE: "gmail",
            SMTP_USER: "example@domain.com",
            SMTP_PASS: "password123;",
            SMTP_FROM: "The One and Only",
            ACCESS_SECRET: "RandomSecret"
        });

        ctx.mock.method(Authenticator.prototype, "getPermissions", (token: string) => ["create:user"]);

        event = {
            version: "2.0",
            routeKey: "POST /users",
            rawPath: "/users",
            rawQueryString: "",
            cookies: ["accessToken=JUnWAetxkoQ23ULDTFhdCu+QbM1kNG3Z5/AP7ufe1BkVqrM2tkevWZVw/bHYEYRk3hS645KILSm4DyJo3dZPFJWUYV/LnJ5z3IishrQcu76YI7MOdTZIp56cnwEI0zY"],
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
                    path: "/users",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "POST /users",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            body: JSON.stringify({
                firstName: "John",
                lastName: "Doe",
                email: "name@example.com",
                permissions: ["create:user", "list:user", "update:user", "delete:user"]
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
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has empty or missing cookies array", async (t) => {
        // Test setup
        event.cookies = [];

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 cookies array has non-parsable elements", async (t) => {
        // Test setup
        event.cookies = ["Not a cookie"];

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("User's access token is invalid", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getPermissions", (token: string) => {
            throw new InvalidTokenError("EVIL Authenticator does not deem you worthy!!");
        })

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("User is not authorized to delete users", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getPermissions", (token: string) => []);

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 403);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
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
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("User with provided email already exists", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                return {
                    $metadata: {},
                    Count: 1
                } satisfies QueryCommandOutput;
            }
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

    test("Verification email template is not present", async (t) => {
        // Test setup
        rfs = (...args: any) => { throw new Error("EVIL node:fs doesn't know how to read!!"); }
        // Test execution & evaluation metrics
        await assert.rejects(import(`../src/index.js?fail=${Date.now()}`));
    });

    test("ejs module throws error", async (t) => {
        // Test setup
        t.mock.method(EJS.prototype, "using", (data: any) => {
            throw new Error("EVIL ejs does not render any templates!!");
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

    test("DynamoDBDocumentClient class throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", (command: any) => {
            throw new Error("EVIL DynamoDB does not like new users on its platform!!");
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

    test("nodemailer module throws error", async (t) => {
        // Test setup
        t.mock.method(Mailer.prototype, "sendHTMLEmail", async (to: string, html: string, title: string) => {
            throw new Error("EVIL nodemailer does not send any emails!!");
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
