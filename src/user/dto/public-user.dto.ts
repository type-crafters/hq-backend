import type { User } from "../user.schema";
import type { ColorScheme } from "./color-scheme.enum";

interface PublicUserArgs {
    firstName: string;
    lastName: string;
    email: string;
    isPasswordSet: boolean;
    profilePictureUrl: string;
    preferredTheme: ColorScheme;
    permissions: string[];
}

export class PublicUser {
    public firstName: string;
    public lastName: string;
    public email: string;
    public isPasswordSet: boolean;
    public profilePictureUrl: string;
    public preferredTheme: ColorScheme;
    public permissions: string[];

    private constructor({
        firstName,
        lastName,
        email,
        isPasswordSet,
        profilePictureUrl,
        preferredTheme,
        permissions
    }: PublicUserArgs) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.isPasswordSet = isPasswordSet;
        this.profilePictureUrl = profilePictureUrl;
        this.preferredTheme = preferredTheme;
        this.permissions = permissions;
    }

    public static ofUser(user: User): PublicUser {
        return new PublicUser({
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            isPasswordSet: !!user.password,
            profilePictureUrl: user.profilePictureUrl,
            preferredTheme: user.preferredTheme,
            permissions: user.permissions
        });
    }
}