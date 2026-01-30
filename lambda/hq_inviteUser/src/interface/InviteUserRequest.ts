export interface InviteUserRequest {
    firstName: string;
    lastName: string;
    email: string;
    [key: string]: unknown;
}