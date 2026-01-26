import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { ApplicationRepository } from "./ApplicationRepository";
import { User } from "../model/User";

export declare class UserRepository extends ApplicationRepository {
    constructor(documentClient: DynamoDBDocumentClient);

    public createUser(user: User): Promise<User>;

    public getById(id: string): Promise<User | null>;
    
    public getByEmail(email: string): Promise<User | null>;

    public deleteById(id: string): Promise<User | null>;

    public updateUser(user: Partial<User>): Promise<User | null>;
}