import type { ColorScheme } from "../enum/ColorScheme.js";
import type { UserStatus } from "../enum/UserStatus.js";
import type { UUID } from "crypto";

export interface UserResponse {
    id: UUID;
    firstName?: string;
    lastName?: string;
    email?: string;
    password?: boolean;
    permissions?: Array<string>;
    status?: UserStatus;
    preferredTheme?: ColorScheme;
    profilePictureUrl?: string;
    [key: string]: any
}