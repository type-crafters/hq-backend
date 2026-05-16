import { IsNotEmpty, IsString } from "class-validator";

export class ReplyToMessageRequest {
    @IsString()
    @IsNotEmpty()
    reply!: string;
}