///<reference types="node"/>
import assert from "node:assert";
import { describe, beforeEach, test, type TestContext } from "node:test";
import { 
    BatchWriteCommand, 
    DynamoDBDocumentClient, 
    QueryCommand, 
    type BatchWriteCommandOutput, 
    type QueryCommandOutput 
} from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { Authenticator, InvalidTokenError } from "@typecrafters/hq-lib";
import { JSONResponse } from "@typecrafters/hq-types";

describe("hq_revokeUserSessions tests", () => {
    let event: APIGatewayProxyEventV2;
    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                return {
                    $metadata: {},
                    Items: [
                        { jti: "texwSCdSf8wgBPvGDqVKIpUeueemIhSlXJ4Sl43gTRw=" },
                        { jti: "texwSCdSf8wgBPvGDqVKIpUeueemIhSlXJ4Sl43gTRw=" },
                        { jti: "texwSCdSf8wgBPvGDqVKIpUeueemIhSlXJ4Sl43gTRw=" },
                    ]
                } satisfies QueryCommandOutput;
            } else if (command instanceof BatchWriteCommand) {
                return {
                    $metadata: {}
                } satisfies BatchWriteCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            REFRESH_TOKEN_TABLE: "RefreshTokenTable",
            REFRESH_SECRET: "RandomSecret"
        });

        ctx.mock.method(Authenticator.prototype, "getSubNoExp", (...args: any[]) => "yes");

        event = {
            version: "2.0",
            routeKey: "DELETE /auth/logout",
            rawPath: "/auth/logout",
            rawQueryString: "",
            cookies: ["refreshToken=fKapVjm11z74Htkj-pImXOS3Lih4qhPdd2ZdkX_n_5"],
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
                    method: "DELETE",
                    path: "/auth/logout",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "DELETE /auth/logout",
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
        t.mock.method(Authenticator.prototype, "getSubNoExp", (token: string) => {
            throw new InvalidTokenError("EVIL Authenticator does not deem you worthy!!");
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
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("DynamoDBDocumentClient class throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            throw new Error("EVIL DynamoDB does not believe in querying tables!!");

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