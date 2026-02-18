import type { ColorScheme } from "../enum/ColorScheme.js";
import type { UserStatus } from "../enum/UserStatus.js";
import type { UUID } from "crypto";

export interface User {
    id: UUID;
    firstName?: string;
    lastName?: string;
    email?: string;
    password?: string | boolean;
    permissions?: Set<string>;
    status?: UserStatus;
    preferredTheme?: ColorScheme;
    profilePictureUrl?: string;
}