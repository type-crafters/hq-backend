export interface UpdateUserRequest {
    firstName?: string;
    lastName?: string;
    email?: string;
    status?: string;
    preferredTheme?: string;
    profilePictureUrl?: string;
    [key: string]: unknown;
}