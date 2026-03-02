/// <reference types="node" />
import assert from "assert";
import { type APIGatewayProxyEventV2 } from "aws-lambda";
import { beforeEach, describe, mock, test, type TestContext } from "node:test";
import { DynamoDBDocumentClient, GetCommand, GetCommandOutput } from "@aws-sdk/lib-dynamodb";
import { JSONResponse, ProjectResponse, ProjectStatus } from "@typecrafters/hq-types";

let gsurl: (...args: any[]) => string;
mock.module("@aws-sdk/s3-request-presigner", {
    namedExports: {
        getSignedUrl: (...args: any[]) => gsurl(...args)
    }
});

describe("hq_getProject tests", () => {
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
                        projectName: "Fatebound",
                        thumbnailUrl: "https://example.com/image.png",
                        status: ProjectStatus.Planning,
                        description: "lorem ipsum dolor sit amet",
                        content: "lorem ipsum dolor sit amet",
                        tags: ["3D", "Action/Adventure", "Open World"],
                        href: "https://www.google.com/",
                        createdAt: Date.now(),
                        lastUpdatedAt: Date.now()
                    }
                } satisfies GetCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            PROJECT_TABLE: "ProjectTable",
            BUCKET: "S3Bucket"
        })

        event = {
            version: "2.0",
            routeKey: "GET /projects/{id}",
            rawPath: "/projects/45f96ae4-e51f-465f-ac81-3dd26dc69e9c",
            rawQueryString: "",
            headers: { "content-type": "application/json" },
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: {
                    method: "GET",
                    path: "/projects/45f96ae4-e51f-465f-ac81-3dd26dc69e9c",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "GET /projects/{id}",
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
        const body: JSONResponse<ProjectResponse> = JSON.parse(response.body);
        assert.ok(body.success);
        assert.ok(body.message);
        assert.ok(body.item && body.item.projectName);
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

    test("Project with the specified id not found", async (t) => {
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