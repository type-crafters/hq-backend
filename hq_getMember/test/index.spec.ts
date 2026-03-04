/// <reference types="node" />
import assert from "assert";
import { type APIGatewayProxyEventV2 } from "aws-lambda";
import { beforeEach, describe, mock, test, type TestContext } from "node:test";
import { DynamoDBDocumentClient, GetCommand, GetCommandOutput } from "@aws-sdk/lib-dynamodb";
import { JSONResponse, MemberItem } from "@typecrafters/hq-types";

let gsurl: (...args: any[]) => string;
mock.module("@aws-sdk/s3-request-presigner", {
    namedExports: {
        getSignedUrl: (...args: any[]) => gsurl(...args)
    }
});

describe("hq_getMember tests", () => {
    let event: APIGatewayProxyEventV2;
    beforeEach((c) => {
        const ctx = c as TestContext;

        gsurl = (...args: any[]) => "s3://image.png?expiresIn=3600";

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof GetCommand) {
                return {
                    $metadata: {},
                    Item: {
                        id: "45f96ae4-e51f-465f-ac81-3dd26dc69e9c",
                        firstName: "John",
                        lastName: "Doe",
                        role: "Game developer & tester",
                        bio: "Lorem ipsum dolor sit amet.",
                        email: "name@example.com",
                        profilePictureUrl: "https://example.com/image.png",
                        since: Date.now(),
                        createdAt: Date.now(),
                        lastUpdatedAt: Date.now()
                    }
                } satisfies GetCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            MEMBER_TABLE: "MemberTable",
            BUCKET: "S3Bucket"
        })

        event = {
            version: "2.0",
            routeKey: "GET /members/{id}",
            rawPath: "/members/45f96ae4-e51f-465f-ac81-3dd26dc69e9c",
            rawQueryString: "",
            headers: { "content-type": "application/json" },
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: {
                    method: "GET",
                    path: "/members/45f96ae4-e51f-465f-ac81-3dd26dc69e9c",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "GET /members/{id}",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            pathParameters: { id: "45f96ae4-e51f-465f-ac81-3dd26dc69e9c" },
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
        const body: JSONResponse<MemberItem> = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
        assert.ok(body.item && body.item.role);
    });

    test("APIGatewayProxyEventV2 has missing path parameters", async (t) => {
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

    test("APIGatewayProxyEventV2 has empty id path parameter", async (t) => {
        // Test setup
        event.pathParameters = {
            id: undefined
        }

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

    test("Team member with the specified id not found", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof GetCommand) {
                return {
                    $metadata: {}
                } satisfies GetCommandOutput;
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

    test("DynamoDBDocumentClient class throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            throw new Error("EVIL DynamoDB will not retrieve your items!!")
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

    test("@aws-sdk/s3-request-presigner module throws error", async (t) => {
        // Test setup
        gsurl = (...args: any[]) => {
            throw new Error("EVIL s3-request-presigner will not sign your URLs!!");
        }

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