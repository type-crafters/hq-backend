import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";


const AWS_REGION = process.env.AWS_REGION;
const TABLE_NAME = process.env.TABLE_NAME;

const db = DynamoDBDocumentClient.from(new DynamoDBClient({ region: AWS_REGION }));

/** @param {import("aws-lambda").APIGatewayProxyEventV2} event */
const handler = async (event) => {
    /* TODO implement */
    return {
        statusCode: 200,
        body: JSON.stringify("Hello from Lambda!")
    };
};

export default handler;