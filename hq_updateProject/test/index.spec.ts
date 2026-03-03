/// <reference types="node" />
import { describe, test, beforeEach, type TestContext } from "node:test";
import assert from "assert";
import { APIGatewayProxyEventV2 } from "aws-lambda";
import { JSONResponse, ProjectStatus } from "@typecrafters/hq-types";
import { DynamoDBDocumentClient, UpdateCommand, UpdateCommandOutput } from "@aws-sdk/lib-dynamodb";

describe("hq_updateProject tests", () => {
    let event: APIGatewayProxyEventV2;

    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof UpdateCommand) {
                return {
                    Attributes: {
                        id: "test-id",
                        projectName: "Updated Project",
                        thumbnailUrl: "https://example.com/updated.png",
                        status: ProjectStatus.Development,
                        description: "Updated description",
                        content: "Updated content",
                        tags: new Set(["3D", "Action"]),
                        createdAt: 1704067200000,
                        lastUpdatedAt: Date.now()
                    },
                    $metadata: {}
                } satisfies UpdateCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            PROJECT_TABLE: "ProjectTable"
        });

        event = {
            version: "2.0",
            routeKey: "PATCH /projects/{id}",
            rawPath: "/projects/test-id",
            rawQueryString: "",
            headers: { "content-type": "application/json" },
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: { method: "PATCH", path: "/projects/test-id", protocol: "HTTP/1.1", sourceIp: "127.0.0.1", userAgent: "node:test" },
                requestId: "12354678",
                routeKey: "PATCH /projects/{id}",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            pathParameters: { id: "test-id" },
            body: JSON.stringify({
                projectName: "Updated Project",
                thumbnailUrl: "https://example.com/updated.png"
            }),
            isBase64Encoded: false
        };
    });

    test("All in order", async (t) => {
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

    test("APIGatewayProxyEventV2 has missing path parameters", async (t) => {
        delete event.pathParameters;

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("APIGatewayProxyEventV2 has empty id path parameter", async (t) => {
        event.pathParameters!.id = "";

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.ok(body.message);
    });

    test("Request body is missing", async (t) => {
        delete event.body;

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.equal(body.message, "Missing or empty request body.");
    });

    test("Request body is malformed JSON", async (t) => {
        event.body = "{ invalid json }";

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
        assert.equal(body.message, "Malformed request body.");
    });

    test("No fields provided for update", async (t) => {
        event.body = JSON.stringify({});

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
    });

    test("Invalid status - not a valid ProjectStatus", async (t) => {
        event.body = JSON.stringify({ status: "InvalidStatus" });

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("Invalid tags - not an array", async (t) => {
        event.body = JSON.stringify({ tags: "not-an-array" });

        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        const body: JSONResponse = JSON.parse(response.body);
        assert.ok(!body.success);
    });

    test("DynamoDBDocumentClient throws error", async (t) => {
        const ctx = t as TestContext;
        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            throw new Error("DynamoDB error");
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