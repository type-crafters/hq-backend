/// <reference types="node" />
import assert from "assert";
import { describe, test, beforeEach, type TestContext } from "node:test";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { Authenticator, InvalidTokenError } from "@typecrafters/hq-lib";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, UpdateCommand, type UpdateCommandOutput } from "@aws-sdk/lib-dynamodb";

describe("hq_updateUser", () => {
    let event: APIGatewayProxyEventV2;
    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof UpdateCommand) {
                const result: UpdateCommandOutput = {
                    $metadata: {}
                };

                if (command.input.ReturnValues === "ALL_NEW") {
                    result.Attributes = {
                        id: "7fbf6fb4-26ab-4bb8-a223-d03f0216c8b9",
                        email: "name@example.com",
                        firstName: "John",
                        lastName: "Doe",
                        password: "$2b$10encryptedPassword",
                        permissions: [
                            "create:user",
                            "delete:user",
                            "list:user",
                            "update:user"
                        ],
                        preferredTheme: "dark",
                        profilePictureUrl: "img/picture.png",
                        status: "active"
                    };
                }

                return result satisfies UpdateCommandOutput;
            }
        });

        ctx.mock.method(Authenticator.prototype, "getPermissions", (token: string) => ["update:user"]);

        ctx.mock.property(process, "env", {
            USER_TABLE: "UserTable"
        });

        event = {
            version: "2.0",
            routeKey: "PATCH /users/7fbf6fb4-26ab-4bb8-a223-d03f0216c8b9",
            rawPath: "/users/7fbf6fb4-26ab-4bb8-a223-d03f0216c8b9",
            rawQueryString: "",
            cookies: ["accessToken=encodedAccessToken"],
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
                    method: "PATCH",
                    path: "/users/7fbf6fb4-26ab-4bb8-a223-d03f0216c8b9",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "PATCH /users/7fbf6fb4-26ab-4bb8-a223-d03f0216c8b9",
                stage: "$default",
                time: new Date().toISOString(),
                timeEpoch: Date.now()
            },
            body: JSON.stringify({
                firstName: "John",
                lastName: "Doe",
                email: "name@example.com"
            }),
            pathParameters: {
                id: "7fbf6fb4-26ab-4bb8-a223-d03f0216c8b9"
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
        const body = JSON.parse(response.body);
        assert.ok(Object.keys(body).length);
    });

    test("APIGatewayProxyEventV2 has a missing or empty cookies array", async (t) => {
        // Test setup
        event.cookies = [];

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
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
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("User's access token is invalid", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getPermissions", (token: string) => {
            throw new InvalidTokenError("EVIL Authenticator does not deem you worthy!!");
        })

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 401);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("User is not authorized to delete users", async (t) => {
        // Test setup
        t.mock.method(Authenticator.prototype, "getPermissions", (token: string) => []);

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 403);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("APIGatewayProxyEventV2 has missing or empty path parameters", async (t) => {
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

    test("APIGatewayProxyEventV2 has malformed required path parameters", async (t) => {
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
            if (command instanceof UpdateCommand) {
                if (command.input.TableName === process.env.USER_TABLE) {
                    throw new ConditionalCheckFailedException({
                        $metadata: {},
                        message: "EVIL DynamoDB will not find the user with this id even if it exists!!"
                    });
                }
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

    test("APIGatewayProxyEventV2 has empty or missing body.", async (t) => {
        // Test setup
        delete event.body;

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("APIGatewayProxyEventV2 has non-JSON parsable body.", async (t) => {
        // Test setup
        event.body = "{ invalid json }";

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("APIGatewayProxyEventV2 body has inappropriate fields", async (t) => {
        // Test setup
        event.body = JSON.stringify({ status: "happy" });

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 400);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
    });

    test("APIGatewayProxyEventV2 body has no fields", async (t) => {
        // Test setup
        event.body = JSON.stringify({});

        // Test execution
        const { handler } = await import("../src/index.js");
        const response = await handler(event);

        // Evaluation metrics
        assert.equal(response.statusCode, 200);
        assert.ok(response.body);
        assert.ok(response.headers && response.headers["Content-Type"]);
        assert.equal(response.headers["Content-Type"], "text/plain");
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
});