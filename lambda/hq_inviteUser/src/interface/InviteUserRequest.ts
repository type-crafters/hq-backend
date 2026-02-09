export interface InviteUserRequest {
    firstName: string;
    lastName: string;
    email: string;
    permissions: string[];
    [key: string]: unknown;
}