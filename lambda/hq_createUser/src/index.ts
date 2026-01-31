import type { APIGatewayProxyEventV2 } from "aws-lambda";

const handler = async (event: APIGatewayProxyEventV2) => {
    /** TODO implement */
    return { 
        statusCode: 200,
        message: JSON.stringify("Hello from Lambda!")
    }
};

export default handler;