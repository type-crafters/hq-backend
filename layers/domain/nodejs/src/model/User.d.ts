import type { Mapper, Supplier } from "../types";
import type { UUID } from "crypto";

declare interface UserArgs {
    id: UUID;
    createdAt: Date;
    email: string;
    firstTimePassword: boolean;
    fullName: string;
    lastUpdatedAt: Date;
    password: string;
    profilePictureUrl: string;
    roles: Set<string>;
}

declare interface UserClaims {
    sub: string;
    email: string;
    roles: string[];
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

    id: UUID;
    createdAt: Date;
    email: string;
    firstTimePassword: boolean;
    fullName: string;
    lastUpdatedAt: Date;
    password: string;
    profilePictureUrl: string;
    roles: Set<string>;

    public getClaims: Supplier<UserClaims>;

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

    static fromCreateRequest: Mapper<CreateUserRequest, User>;

    static fromItem: Mapper<UserItem, User>;
}