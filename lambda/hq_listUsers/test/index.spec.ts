/// <reference types="node" />
import assert from "assert";
import { describe, test, beforeEach, mock, type TestContext } from "node:test";
import { DynamoDBDocumentClient, ScanCommand, type ScanCommandOutput } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";

describe("hq_listUsers", () => {
    let event: APIGatewayProxyEventV2;

    let gsurl: (...args: any[]) => string;

    mock.module("@aws-sdk/s3-request-presigner", {
        namedExports: {
            getSignedUrl: (...args: any[]) => gsurl(args)
        }
    });


    beforeEach((c) => {
        const ctx = c as TestContext;

        gsurl = (...args: any[]) => "s3://example.com/mock-media.png?argv0=something&argv1=else"

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof ScanCommand) {
                return {
                    $metadata: {},
                    Items: [
                        {
                            id: "0c70d7f1-5a5b-4d41-b614-b6a1d6ba8861",
                            email: "alex.ramirez@example.com",
                            firstName: "Alex",
                            lastName: "Ramirez",
                            password: "$2b$10encryptedpassword",
                            permissions: [
                                "create:user",
                                "delete:user",
                                "list:user",
                                "update:user"
                            ],
                            preferredTheme: "dark",
                            profilePictureUrl: "img/link-profile-picture.png",
                            status: "active"
                        },
                        {
                            id: "b1e3d2c7-8a4f-4d7a-9e52-2f4b1d0f3c91",
                            email: "sofia.martinez@example.com",
                            firstName: "Sofia",
                            lastName: "Martinez",
                            password: "$2b$10encryptedpassword",
                            permissions: [
                                "create:user",
                                "list:user",
                                "update:user"
                            ],
                            preferredTheme: "light",
                            profilePictureUrl: "img/link-profile-picture.png",
                            status: "active"
                        },
                        {
                            id: "5f9d0a7b-3b2e-4e0c-b1f3-7d8a9c2e6f44",
                            email: "jordan.lee@example.com",
                            firstName: "Jordan",
                            lastName: "Lee",
                            password: "$2b$10encryptedpassword",
                            permissions: ["list:user"],
                            preferredTheme: "dark",
                            profilePictureUrl: "img/link-profile-picture.png",
                            status: "inactive"
                        }
                    ]
                } satisfies ScanCommandOutput;
            }
        });

        ctx.mock.property(process, "env", {
            BUCKET: "S3Bucket",
            USER_TABLE: "UserTable"
        });

        event = {
            version: "2.0",
            routeKey: "GET /users",
            rawPath: "/users",
            rawQueryString: "limit=30&cursor=eyJpZCI6IjAzNTNmZDVlLTVjNWYtNDgxMC1hOTY5LThlYjJhMjIwMjI1OSJ9",
            cookies: ["accessToken=jsonwebtoken"],
            headers: {
                "user-agent": "node:test",
                "host": "example.execute-api.us-east-1.amazonaws.com"
            },
            queryStringParameters: {
                limit: "30",
                cursor: "eyJpZCI6IjAzNTNmZDVlLTVjNWYtNDgxMC1hOTY5LThlYjJhMjIwMjI1OSJ9"
            },
            requestContext: {
                accountId: "123456789012",
                apiId: "testAPI",
                domainName: "example.execute-api.us-east-1.amazonaws.com",
                domainPrefix: "example",
                http: {
                    method: "GET",
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
        const body = JSON.parse(response.body);
        assert.ok(body && body.items);
    });

    test("APIGatewayProxyEventV2 has empty or missing querystring parameters", async (t) => {
        // Test setup
        event.rawQueryString = "";
        delete event.queryStringParameters;

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body = JSON.parse(response.body);
        assert.ok(body && body.items);
    });

    test("APIGatewayProxyEventV2 has malformed querystring parameters", async (t) => {
        // Test setup
        event.rawQueryString = "limit=Not%20a%20Number&cursor=Not%20an%20Object"
        event.queryStringParameters = { limit: "Not a Number", cursor: "Not an Object" };

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "application/json");
        const body = JSON.parse(response.body);
        assert.ok(body && body.items);
    });

    test("No users were found", async (t) => {
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
        const body = JSON.parse(response.body);
        assert.ok(body && body.items && !body.items.length);
    });

    test("DynamoDBDocumentClient class throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", (command: any) => {
            throw new Error("EVIL DynamoDB will not search your tables!!");
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 500);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("S3 Request Presigner module throws error", async (t) => {
        // Test setup
        gsurl = (...args: any[]) => { throw new Error("EVIL @aws-sdk/s3-request-presigner forgot how to sign!!"); }

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 500);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });
});
