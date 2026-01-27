import { randomUUID } from "crypto";

export class User {
    static #EMPTY_IMAGE_KEY = "/img/placeholder.svg";
    id;
    createdAt;
    email;
    firstTimePassword;
    fullName;
    lastUpdatedAt;
    password;
    profilePictureUrl;
    roles;

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
    } = {}) {
        this.id = id;
        this.createdAt = createdAt;
        this.email = email;
        this.firstTimePassword = firstTimePassword;
        this.fullName = fullName;
        this.lastUpdatedAt = lastUpdatedAt;
        this.password = password;
        this.profilePictureUrl = profilePictureUrl;
        this.roles = roles;
    }

    getClaims() {
        return {
            sub: this.id,
            email,
            roles: Array.from(roles)
        }
    }

    static fromCreateRequest(body) {
        const {
            email,
            fullName,
            password,
            roles
        } = body;

        const now = new Date();

        return new User({
            id: randomUUID(),
            createdAt: now,
            email: email.toLowerCase(),
            firstTimePassword: true,
            fullName,
            lastUpdatedAt: now,
            password,
            profilePictureUrl: this.#EMPTY_IMAGE_KEY,
            roles: new Set(roles)
        });
    }

    static fromItem(Item) {
        const {
            id,
            createdAt,
            email,
            firstTimePassword,
            fullName,
            lastUpdatedAt,
            password,
            profilePictureUrl,
            roles
        } = Item;

        if (!id || typeof id !== "string") {
            throw new TypeError("Inappropriate partition key for User");
        }

        return new User({
            id,
            createdAt: new Date(createdAt),
            email,
            firstTimePassword,
            fullName,
            lastUpdatedAt: new Date(lastUpdatedAt),
            password,
            profilePictureUrl,
            roles
        });
    }
}