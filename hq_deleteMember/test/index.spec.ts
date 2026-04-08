/// <reference types="node" />
import {
    describe,
    test,
    beforeEach,
    afterEach,
    type TestContext,
} from "node:test";
import assert from "assert";
import { JSONResponse } from "@typecrafters/hq-types";
import { APIGatewayProxyEventV2 } from "aws-lambda";
import {
    DeleteCommand,
    DeleteCommandOutput,
    DynamoDBDocumentClient,
} from "@aws-sdk/lib-dynamodb";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { Authenticator, InvalidTokenError } from "@typecrafters/hq-lib";

describe("hq_deleteMember tests", () => {
    let event: APIGatewayProxyEventV2;
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(
            Authenticator.prototype,
            "getPermissions",
            (...args: any[]) => ["delete:member"],
        );

        ctx.mock.method(
            DynamoDBDocumentClient.prototype,
            "send",
            async (command: any) => {
                if (command instanceof DeleteCommand) {
                    return {
                        $metadata: {},
                    } satisfies DeleteCommandOutput;
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
            routeKey: "DELETE /members/{id}",
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
                    method: "DELETE",
                    path: "/members/member_123",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test",
                },
                requestId: "12354678",
                routeKey: "DELETE /members/{id}",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now(),
            },
            pathParameters: {
                id: "member_123",
            },
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

    test("APIGatewayProxyEventV2 contains malformed cookies", async () => {
        event.cookies = ["{ invalid cookie }"];

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

    test("User is not authorized to delete team members", async (t) => {
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

    test("APIGatewayProxyEventV2 has missing pathParameters", async () => {
        delete event.pathParameters;

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("APIGatewayProxyEventV2 has pathParameters without id", async () => {
        event.pathParameters = {};

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("Delete command fails because team member does not exist", async (t) => {
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async () => {
            throw new ConditionalCheckFailedException({
                $metadata: {},
                message: "Team member not found",
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
                "EVIL DynamoDB will not delete your team member information!!",
            );
        });

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 500);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });
});
