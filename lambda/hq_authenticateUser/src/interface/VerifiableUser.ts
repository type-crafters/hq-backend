export interface VerifiableUser {
    id: string;
    email: string;
    password: string;
    roles: Set<string>;
}