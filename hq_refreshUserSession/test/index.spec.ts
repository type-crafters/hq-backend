/// <reference types="node" />
import { APIGatewayProxyEventV2 } from "aws-lambda";
import { JSONResponse } from "@typecrafters/hq-types";
import assert from "node:assert";
import { describe, test, beforeEach, TestContext } from "node:test";
import { Authenticator, ExpiredTokenError, InvalidTokenError } from "@typecrafters/hq-lib";
import { DeleteCommand, DeleteCommandOutput, DynamoDBDocumentClient, PutCommand, PutCommandOutput } from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";

describe("hq_refreshUserSession tests", () => {
    let event: APIGatewayProxyEventV2;
    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof DeleteCommand) {
                return {
                    $metadata: {}
                } satisfies DeleteCommandOutput;
            } else if (command instanceof PutCommand) {
                return {
                    $metadata: {}
                } satisfies PutCommandOutput;
            }
        });

        ctx.mock.method(Authenticator.prototype, "getClaims", (...args: any) => ({
            jti: "be38eb89-2c11-4f6d-9ea5-491e0dd16257",
            sub: "13820524-299b-41f5-adca-1c02316b27bf",
            exp: Date.now() + 86_400_00
        }));
        ctx.mock.method(Authenticator.prototype, "getClaimsNoExp", (...args: any) => ({
            sub: "13820524-299b-41f5-adca-1c02316b27bf",
            eml: "name@example.com",
            prm: ["list:user"]
        }));

        ctx.mock.property(process, "env", {
            REFRESH_TOKEN_TABLE: "RefreshTokenTable",
            REFRESH_SECRET: "refresh_secret",
            ACCESS_SECRET: "access_secret",
            JTI_SECRET: "jti_secret"
        });

        event = {
            version: "2.0",
            routeKey: "GET /auth/refresh",
            rawPath: "/auth/refresh",
            rawQueryString: "",
            cookies: [
                "accessToken=inXIHp-epkvNwC-xd1fm4JUwkY7PpWwnhpGyOxo15aM",
                "refreshToken=UZyYf3X8xVwkIDffR4sqVIrjD8-yln_RCFI8NUqJz4Y"
            ],
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
                    method: "GET",
                    path: "/auth/refresh",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "GET /auth/refresh",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            body: undefined,
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
        const body: JSONResponse = JSON.parse(response.body);
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has an empty or missing cookies array", async (t) => {
        // Test setup
        delete event.cookies;

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Cookies array contains non-parsable cookies", async (t) => {
        // Test setup
        event.cookies = ["&nothing;"]

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Request cookies are missing required values", async (t) => {
        // Test setup
        event.cookies = ["accessToken=oJ60BSi8rUsGIU5s2GbnH_utt9lNWBYRTLkG9YdVzv0"]

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Access or refresh token signatures are invalid", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getClaims", (...args: any) => {
            throw new InvalidTokenError("EVIL Authenticator sees all tokens as invalid!!");
        });

        t.mock.method(Authenticator.prototype, "getClaimsNoExp", (...args: any) => {
            throw new InvalidTokenError("EVIL Authenticator sees all tokens as invalid!!");
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
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Refresh token is expired", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getClaims", (...args: any) => {
            throw new ExpiredTokenError("EVIL Authenticator comes from a future where this token is already expired!!");
        });

        t.mock.method(Authenticator.prototype, "getClaimsNoExp", (...args: any) => {
            throw new ExpiredTokenError("EVIL Authenticator comes from a future where this token is already expired!!");
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
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Refresh token is malformed", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getClaims", (...args: any) => ({}));
        t.mock.method(Authenticator.prototype, "getClaimsNoExp", (...args: any) => ({}));

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Access and refresh token subjects do not match", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getClaims", (...args: any) => ({
            sub: "f2c77de0-25a0-4db0-8cd9-b0722bcc9483"
        }));
        t.mock.method(Authenticator.prototype, "getClaimsNoExp", (...args: any) => ({
            sub: "ed27e5f-55bd-41e4-9a21-e8c840b4bc38"
        }));


        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Token with the provided JTI hash does not exist", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof DeleteCommand) {
                throw new ConditionalCheckFailedException({
                    $metadata: {},
                    message: "EVIL DynamoDB won't find any JTIs!!"
                });
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
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("DynamoDBDocumentClient class throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            throw new Error("EVIL DynamoDB will not operate on any refresh tokens!!");
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
        console.log("\x1b[33m" + body.message + "\x1b[0m");
        assert.ok(!body.success);
        assert.ok(body.message);
    });

});