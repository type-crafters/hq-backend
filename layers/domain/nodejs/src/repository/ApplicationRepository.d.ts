import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { RequiresEnvironment } from "../lib/RequiresEnvironment";

export declare abstract class ApplicationRepository extends RequiresEnvironment {
    protected documentClient: DynamoDBDocumentClient;

    protected constructor(documentClient: DynamoDBDocumentClient);
}