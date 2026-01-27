import type { Nullable } from "../types";
import type { DynamoDBDocumentClient } from "@aws-sdk/lib-dynamodb";
import { ApplicationRepository } from "./ApplicationRepository";
import { User } from "../model/User";

export declare class UserRepository extends ApplicationRepository {
    constructor(documentClient: DynamoDBDocumentClient);

    public createUser(user: User): Promise<User>;

    public getById(id: string): Promise<Nullable<User>>;
    
    public getByEmail(email: string): Promise<Nullable<User>>;

    public deleteById(id: string): Promise<Nullable<User>>;

    public updateUser(user: Partial<User>): Promise<Nullable<User>>;
}