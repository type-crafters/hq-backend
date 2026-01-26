import type { UUID } from "crypto";

declare interface UserArgs {
    public id: UUID;
    public createdAt: Date;
    public email: string;
    public firstTimePassword: boolean;
    public fullName: string;
    public lastUpdatedAt: Date;
    public password: string;
    public profilePictureUrl: string;
    public roles: Set<string>;
}

declare interface CreateUserRequest {
    email: string;
    fullName: string;
    password: string;
    roles: string[];
    [key: string]: unknown;
}

declare interface UserItem {
    id: string;
    createdAt: string;
    email: string;
    firstTimePassword: boolean;
    fullName: string;
    lastUpdatedAt: string;
    password: string;
    profilePictureUrl: string;
    roles: Set<string>;
    [key: string]: unknown;
}

export declare class User {
    private static EMPTY_IMAGE_KEY: string;

    public id: UUID;
    public createdAt: Date;
    public email: string;
    public firstTimePassword: boolean;
    public fullName: string;
    public lastUpdatedAt: Date;
    public password: string;
    public profilePictureUrl: string;
    public roles: Set<string>;

    constructor({
        id,
        createdAt,
        email,
        firstTimePassword,
        fullName,
        lastUpdatedAt,
        password,
        profilePictureUrl,
        roles,
    }: UserArgs);

    public static fromCreateRequest(body: CreateUserRequest): User;

    public static fromItem(Item): User;
}