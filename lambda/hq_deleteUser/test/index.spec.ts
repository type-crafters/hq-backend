///<reference types="node"/>
import assert from "node:assert";
import { describe, beforeEach, test, type TestContext } from "node:test";
import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { DeleteCommand, DeleteCommandOutput, DynamoDBDocumentClient, QueryCommand, type QueryCommandOutput } from "@aws-sdk/lib-dynamodb";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { DeleteObjectsCommand, DeleteObjectsCommandOutput, ListObjectsV2Command, ListObjectsV2CommandOutput, S3Client } from "@aws-sdk/client-s3";
import { Authenticator, InvalidTokenError } from "@typecrafters/hq-lib";

describe("hq_deleteUser", () => {
    let event: APIGatewayProxyEventV2;
    beforeEach((c) => {
        const ctx = c as TestContext;

        ctx.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                return {
                    $metadata: {},
                    Items: [
                        {
                            jti: "V3Cf5-ALwXu6leUvZahiUR_L-4Wujoc0qWHH7_lOjkM",
                            exp: new Date().getTime() / 1000,
                            iat: new Date().getTime() / 1000,
                            iss: "it's a me, Mario!",
                            sub: "93daa991-e5b1-4c4e-9a97-db5ffdbd5d59",
                            typ: "refresh"
                        },
                        {
                            jti: "utjfB1h44sWe8iB3e-PagGg27zTsY42gLiFl10s1LMA",
                            exp: new Date().getTime() / 1000,
                            iat: new Date().getTime() / 1000,
                            iss: "it's a me, Mario!",
                            sub: "93daa991-e5b1-4c4e-9a97-db5ffdbd5d59",
                            typ: "refresh"
                        }
                    ]
                } satisfies QueryCommandOutput;
            } else if (command instanceof DeleteCommand) {
                return {
                    $metadata: {}
                } satisfies DeleteCommandOutput;
            } else {
                throw new Error("hq_deleteUser::handler called DynamoDBDocumentClient.send with an unexpected command.");
            }
        });

        ctx.mock.method(S3Client.prototype, "send", async (command: any) => {
            if (command instanceof ListObjectsV2Command) {
                return {
                    $metadata: {},
                    Contents: [
                        {
                            Key: "/img/pfp-someone.png",
                            LastModified: new Date(),
                            Size: 1_280_000
                        },
                        {
                            Key: "/img/pfp-someone2.png",
                            LastModified: new Date(),
                            Size: 1_050_000
                        }

                    ]
                } satisfies ListObjectsV2CommandOutput;
            } else if (command instanceof DeleteObjectsCommand) {
                return {
                    $metadata: {}
                } satisfies DeleteObjectsCommandOutput
            }
        });

        ctx.mock.method(Authenticator.prototype, "getPermissions", (token: string) => ["delete:user"]);

        ctx.mock.property(process, "env", {
            BUCKET: "S3BucketName",
            USER_TABLE: "DynamoDBUserTable",
            REFRESH_TOKEN_TABLE: "DynamoDBRefreshTokenTable"
        });

        event = {
            version: "2.0",
            routeKey: "DELETE /users/f1e48697-c954-4ebf-b28d-17c3541268d7",
            rawPath: "/users/f1e48697-c954-4ebf-b28d-17c3541268d7",
            rawQueryString: "",
            cookies: ["accessToken=JUnWAetxkoQ23ULDTFhdCu+QbM1kNG3Z5/AP7ufe1BkVqrM2tkevWZVw/bHYEYRk3hS645KILSm4DyJo3dZPFJWUYV/LnJ5z3IishrQcu76YI7MOdTZIp56cnwEI0zY"],
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
                    method: "DELETE",
                    path: "/users/f1e48697-c954-4ebf-b28d-17c3541268d7",
                    protocol: "HTTP/1.1",
                    sourceIp: "127.0.0.1",
                    userAgent: "node:test"
                },
                requestId: "12354678",
                routeKey: "DELETE /users/f1e48697-c954-4ebf-b28d-17c3541268d7",
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
        assert.equal(response.statusCode, 204);
        assert.ok(!response.body);
        assert.ok(!response.headers);
    });

    test("APIGatewayProxyEventV2 has empty or missing cookies array", async (t) => {
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
            if (command instanceof DeleteCommand) {
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

    test("S3 ListObjectsV2Command throws error", async (t) => {
        // Test setup
        t.mock.method(S3Client.prototype, "send", async (command: any) => {
            if (command instanceof ListObjectsV2Command) {
                throw new Error("EVIL S3 will keep your bucket to itself!!");
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

    test("DynamoDB QueryCommand throws error", async (t) => {
        // Test setup
        t.mock.method(DynamoDBDocumentClient.prototype, "send", async (command: any) => {
            if (command instanceof QueryCommand) {
                throw new Error("EVIL DynamoDB does not believe in querying tables!!");
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