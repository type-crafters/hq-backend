import { UUID } from "crypto";
import { UserStatus } from "../enum/UserStatus.js";

export interface UserInviteItem {
    id: UUID;
    firstName: string;
    lastName: string;
    email: string;
    status: UserStatus;
}