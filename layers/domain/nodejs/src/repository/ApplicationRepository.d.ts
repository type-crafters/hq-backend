import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";

export declare abstract class ApplicationRepository {
    protected _documentClient: DynamoDBDocumentClient;
    protected _requiredEnvVars: string[];
    protected _environment: Map<string, string>;

    constructor(documentClient: DynamoDBDocumentClient);
    
    public setEnvironment(environment: NodeJS.ProcessEnv);

    protected _checkEnvionment();
}