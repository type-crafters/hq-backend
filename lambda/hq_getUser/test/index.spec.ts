import { DynamoDBDocumentClient, GetCommand, GetCommandOutput } from "@aws-sdk/lib-dynamodb";
import assert from "assert";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { beforeEach, describe, test, type TestContext } from "node:test";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";

describe("hq_getUser", () => {
    let event: APIGatewayProxyEventV2;

    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.module("@aws-sdk/s3-request-presigner", {
            namedExports: {
                getSignedUrl: async (client: S3Client, command: any, options?: Record<string, any>) => {
                    void (client && options);
                    if (command instanceof GetObjectCommand) {
                        return "s3://example.com/signedUrl?signature=this&expiresIn=3600";
                    }
                    return "";
                }
            }
        });

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof GetCommand) {
                return {
                    $metadata: {},
                    Item: {
                        id: "f1e48697-c954-4ebf-b28d-17c3541268d7",
                        firstName: "John",
                        lastName: "Doe",
                        email: "name@example.com",
                        password: "$2b$10$usOXyHIzq/TiHKmjAsIaCefxXJxGtHjgjJtNMErAhT6RwOhKT/dG2",
                        permissions: new Set(["create:user", "list:user", "update:user", "delete:user"]),
                        status: "active",
                        preferredTheme: "system",
                        profilePictureUrl: "/img/link-profile-picture.png"
                    }
                } satisfies GetCommandOutput;
            }
        });

        console.log(import.meta.url);

        ctx.mock.property(process, "env", {
            BUCKET: "S3BucketName",
            USER_TABLE: "DynamoDBUserTable",
        });

        event = {
            version: "2.0",
            routeKey: "GET /users/f1e48697-c954-4ebf-b28d-17c3541268d7",
            rawPath: "/users/f1e48697-c954-4ebf-b28d-17c3541268d7",
            rawQueryString: "",
            cookies: [],
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
                    path: "/users/f1e48697-c954-4ebf-b28d-17c3541268d7",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "GET /users/f1e48697-c954-4ebf-b28d-17c3541268d7",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            body: undefined,
            pathParameters: {
                id: "f1e48697-c954-4ebf-b28d-17c3541268d7"
            },
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
        const data = JSON.parse(response.body);
        assert(data && Object.keys(data).length);
        assert(data.id);
        assert(data.password && typeof data.password === "boolean");
        assert(data.permissions && data.permissions instanceof Array);
    });

    test("APIGatewayProxyEventV2 has empty or missing path string", async (t) => {
        // Test setup
        event.rawPath = "";
        event.requestContext.http.path = "";
        event.pathParameters = {};

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("APIGatewayProxyEventV2 pathParameters is missing required attributes", async (t) => {
        // Test setup
        event.pathParameters = { id: undefined };

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("User with provided id does not exist", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof GetCommand) {
                return {
                    $metadata: {},
                    Item: undefined
                };
            }
        });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 404);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("User item does not contain a 'profilePictureUrl' attribute", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof GetCommand) {
                return {
                    $metadata: {},
                    Item: {
                        id: "f1e48697-c954-4ebf-b28d-17c3541268d7",
                        firstName: "John",
                        lastName: "Doe",
                        email: "name@example.com",
                        password: "$2b$10$usOXyHIzq/TiHKmjAsIaCefxXJxGtHjgjJtNMErAhT6RwOhKT/dG2",
                        permissions: new Set(["create:user", "list:user", "update:user", "delete:user"]),
                        status: "active",
                        preferredTheme: "system",
                    }
                } satisfies GetCommandOutput;
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
        const data = JSON.parse(response.body);
        assert(data && Object.keys(data).length);
        assert(!data.profilePictureUrl);
    });

    test("DynamoDB GetCommand throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof GetCommand) {
                throw new Error("EVIL DynamoDB will not find any users, even if they exist!!");
            }
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
});
