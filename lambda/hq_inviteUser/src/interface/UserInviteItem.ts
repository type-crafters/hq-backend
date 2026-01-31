import { UUID } from "crypto";
import { VerificationStatus } from "../enum/VerificationStatus.js";

export interface UserInviteItem {
    id: UUID;
    firstName: string;
    lastName: string;
    email: string;
    status: VerificationStatus;
}