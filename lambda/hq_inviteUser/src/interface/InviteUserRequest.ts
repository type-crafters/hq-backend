export interface InviteUserRequest {
    firstName: string;
    lastName: string;
    email: string;
    roles: string[];
    [key: string]: unknown;
}