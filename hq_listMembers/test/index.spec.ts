/// <reference types="node" />
import assert from "assert";
import { type APIGatewayProxyEventV2 } from "aws-lambda";
import { beforeEach, describe, mock, test, type TestContext } from "node:test";
import { DynamoDBDocumentClient, ScanCommand, ScanCommandOutput } from "@aws-sdk/lib-dynamodb";
import { JSONResponse, MemberItem } from "@typecrafters/hq-types";

let gsurl: (...args: any[]) => string;
mock.module("@aws-sdk/s3-request-presigner", {
    namedExports: {
        getSignedUrl: (...args: any[]) => gsurl(...args)
    }
});

describe("hq_listMembers tests", () => {
    let event: APIGatewayProxyEventV2;
    beforeEach((c) => {
        const ctx = c as TestContext;

        gsurl = (...args: any[]) => "s3://image.png?expiresIn=3600";

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof ScanCommand) {
                return {
                    $metadata: {},
                    Items: [
                        {
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
                    ],
                    LastEvaluatedKey: undefined
                } satisfies ScanCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            MEMBER_TABLE: "MemberTable",
            BUCKET: "S3Bucket"
        })

        event = {
            version: "2.0",
            routeKey: "GET /members",
            rawPath: "/members",
            rawQueryString: "",
            headers: { "content-type": "application/json" },
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: {
                    method: "GET",
                    path: "/members",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "GET /members",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            body: undefined,
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
        assert.ok(body.items && body.items.length > 0);
    });

    test("No team members retrieved", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof ScanCommand) {
                return {
                    $metadata: {},
                    Items: []
                } satisfies ScanCommandOutput;
            }
        });

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

    test("Query with invalid limit parameter", async (t) => {
        // Test setup
        event.rawQueryString = "limit=invalid";
        event.queryStringParameters = { limit: "invalid" };

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
    });

    test("Query with valid cursor parameter", async (t) => {
        // Test setup
        const cursorObj = { id: "45f96ae4-e51f-465f-ac81-3dd26dc69e9c" };
        const cursorEncoded = Buffer.from(JSON.stringify(cursorObj)).toString("base64url");
        event.rawQueryString = `cursor=${cursorEncoded}`;
        event.queryStringParameters = { cursor: cursorEncoded };

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
    });

    test("Query with invalid cursor parameter", async (t) => {
        // Test setup
        event.rawQueryString = "cursor=invalid!!!";
        event.queryStringParameters = { cursor: "invalid!!!" };

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
    });

    test("Response includes cursor when LastEvaluatedKey exists", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof ScanCommand) {
                return {
                    $metadata: {},
                    Items: [
                        {
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
                    ],
                    LastEvaluatedKey: { id: "45f96ae4-e51f-465f-ac81-3dd26dc69e9c" }
                } satisfies ScanCommandOutput;
            }
        });

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
        assert.ok(body.cursor);
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