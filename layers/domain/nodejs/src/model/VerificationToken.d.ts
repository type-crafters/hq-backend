import { Mapper, Supplier } from "../types";

export declare interface VerificationTokenItem {
    hash: string;
    type: string;
    ttl: number;
}

export declare interface VerificationTokenArgs {
    hash: string;
    type: string;
    ttl: Date;
}

export declare class VerificationToken {
    private static EMAIL_EXPIRY: number;
    private static PASSWORD_EXPIRY: number;
    public static readonly VERIFY_EMAIL: "VERIFY_EMAIL";
    public static readonly RESET_PASSWORD: "RESET_PASSWORD";

    hash: string;
    type: "VERIFY_EMAIL" | "RESET_PASSWORD";
    ttl: Date;

    public toItem: Supplier<VerificationTokenItem>;
    public static forEmailVerification: Mapper<string, VerificationToken>;
    public static forPasswordReset: Mapper<string, VerificationToken>;
}