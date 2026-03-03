/// <reference types="node" />
import { describe, test, beforeEach, afterEach, type TestContext } from "node:test";
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

describe("hq_deleteProject tests", () => {
    let event: APIGatewayProxyEventV2;
    let originalEnv: NodeJS.ProcessEnv;

    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(
            Authenticator.prototype,
            "getPermissions",
            (...args: any[]) => ["delete:project"],
        );

        ctx.mock.method(
            DynamoDBDocumentClient.prototype,
            "send",
            async (command: any) => {
                if (command instanceof DeleteCommand)
                    return {
                        $metadata: {},
                    } satisfies DeleteCommandOutput;
            },
        );

        originalEnv = process.env;
        process.env = {
            ...process.env,
            PROJECT_TABLE: "ProjectTable",
            ACCESS_SECRET: "access_secret",
        };

        event = {
            version: "2.0",
            routeKey: "DELETE /projects/{id}",
            rawPath: "/projects/project_123",
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
                    path: "/projects/project_123",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test",
                },
                requestId: "12354678",
                routeKey: "DELETE /projects/{id}",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now(),
            },
            pathParameters: {
                id: "project_123",
            },
            isBase64Encoded: false,
            stageVariables: {},
        };
    });

    afterEach(() => {
        process.env = originalEnv;
    });

    test("All in order", async (t) => {
        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        console.log(response.body);
        // Evaluation metrics
        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has a missing cookies array", async (t) => {
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
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 contains malformed cookies", async (t) => {
        // Test setup
        event.cookies = ["{ invalid cookie }"];

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

    test("Cookies array is missing accessToken cookie", async (t) => {
        // Test setup
        event.cookies = [
            "refreshToken=RscHaYs-JkVKhM4H2xAISIUXsogAWnTzyc5MTY3pZqc",
        ];

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

    test("accessToken cookie is invalid or expired", async (t) => {
        // Test setup
        t.mock.method(
            Authenticator.prototype,
            "getPermissions",
            (...args: any) => {
                throw new InvalidTokenError(
                    "EVIL Authenticator invalidates all your tokens!!",
                );
            },
        );

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

    test("User is not authorized to delete projects", async (t) => {
        // Test setup
        t.mock.method(
            Authenticator.prototype,
            "getPermissions",
            (...args: any) => [],
        );

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

    test("APIGatewayProxyEventV2 has missing pathParameters", async (t) => {
        // Test setup
        delete event.pathParameters;

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

    test("APIGatewayProxyEventV2 has pathParameters without id", async (t) => {
        // Test setup
        event.pathParameters = {};

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

    test("Delete command fails because project does not exist", async (t) => {
        // Test setup
        t.mock.method(
            DynamoDBDocumentClient.prototype,
            "send",
            async (command: any) => {
                throw new ConditionalCheckFailedException({
                    $metadata: {},
                    message: "Project not found",
                });
            },
        );

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

    test("DynamoDBDocumentClient class throws error", async (t) => {
        // Test setup
        t.mock.method(
            DynamoDBDocumentClient.prototype,
            "send",
            async (command: any) => {
                throw new Error(
                    "EVIL DynamoDB will not delete your project information!!",
                );
            },
        );

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
