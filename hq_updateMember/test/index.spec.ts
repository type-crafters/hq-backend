/// <reference types="node" />
import {
    describe,
    test,
    beforeEach,
    afterEach,
    type TestContext,
} from "node:test";
import assert from "assert";
import { APIGatewayProxyEventV2 } from "aws-lambda";
import { JSONResponse } from "@typecrafters/hq-types";
import {
    DynamoDBDocumentClient,
    UpdateCommand,
    UpdateCommandOutput,
} from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { Authenticator, InvalidTokenError } from "@typecrafters/hq-lib";

describe("hq_updateMember tests", () => {
    let event: APIGatewayProxyEventV2;
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(
            Authenticator.prototype,
            "getPermissions",
            (...args: any[]) => ["update:member"],
        );

        ctx.mock.method(
            DynamoDBDocumentClient.prototype,
            "send",
            async (command: any) => {
                if (command instanceof UpdateCommand) {
                    return {
                        Attributes: {
                            id: "member_123",
                            firstName: "Updated",
                            lastName: "Doe",
                            role: "Lead Dev",
                            bio: "Updated bio",
                            email: "updated@example.com",
                            profilePictureUrl:
                                "https://example.com/updated.png",
                            since: 1710000000000,
                            createdAt: 1700000000000,
                            lastUpdatedAt: Date.now(),
                        },
                        $metadata: {},
                    } satisfies UpdateCommandOutput;
                }
            },
        );

        originalEnv = process.env;
        process.env = {
            ...process.env,
            MEMBER_TABLE: "MemberTable",
            ACCESS_SECRET: "access_secret",
        };

        event = {
            version: "2.0",
            routeKey: "PATCH /members/{id}",
            rawPath: "/members/member_123",
            rawQueryString: "",
            cookies: [
                "accessToken=inXIHp-epkvNwC-xd1fm4JUwkY7PpWwnhpGyOxo15aM",
            ],
            headers: {
                "content-type": "application/json",
                "user-agent": "node:test",
                host: "example.execute-api.us-east-1.amazonaws.com",
            },
            queryStringParameters: {},
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: {
                    method: "PATCH",
                    path: "/members/member_123",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test",
                },
                requestId: "12354678",
                routeKey: "PATCH /members/{id}",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now(),
            },
            pathParameters: { id: "member_123" },
            body: JSON.stringify({
                firstName: "Updated",
                role: "Lead Dev",
            }),
            isBase64Encoded: false,
            stageVariables: {},
        };
    });

    afterEach(() => {
        process.env = originalEnv;
    });

    test("All in order", async () => {
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
        assert.ok(body.item);
    });

    test("APIGatewayProxyEventV2 has a missing cookies array", async () => {
        delete event.cookies;

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("Cookies array is missing accessToken cookie", async () => {
        event.cookies = ["refreshToken=abc123"];

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("accessToken cookie is invalid or expired", async (t) => {
        t.mock.method(
            Authenticator.prototype,
            "getPermissions",
            (...args: any) => {
                throw new InvalidTokenError("Invalid token");
            },
        );

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
    });

    test("User is not authorized to update team members", async (t) => {
        t.mock.method(
            Authenticator.prototype,
            "getPermissions",
            (...args: any) => [],
        );

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 403);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("APIGatewayProxyEventV2 has missing path parameters", async () => {
        delete event.pathParameters;

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("APIGatewayProxyEventV2 has empty id path parameter", async () => {
        event.pathParameters = {};

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("Request body is missing", async () => {
        delete event.body;

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.equal(body.message, "Missing or empty request body.");
    });

    test("Request body is malformed JSON", async () => {
        event.body = "{ invalid json }";

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.equal(body.message, "Malformed request body.");
    });

    test("No fields provided for update", async () => {
        event.body = JSON.stringify({});

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.equal(body.message, "No fields updated.");
    });

    test("Request body has invalid fields", async () => {
        event.body = JSON.stringify({
            firstName: 123,
        });

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("Team member with the specified id not found", async (t) => {
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async () => {
            throw new ConditionalCheckFailedException({
                $metadata: {},
                message: "Not found",
            });
        });

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 404);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("DynamoDBDocumentClient class throws error", async (t) => {
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async () => {
            throw new Error(
                "EVIL DynamoDB will not update your team member information!!",
            );
        });

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 500);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.equal(body.message, "A server-side error occurred.");
    });
});
