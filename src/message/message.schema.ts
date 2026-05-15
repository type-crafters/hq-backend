import type { MessageStatus } from "./dto/message-status.enum";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import type { HydratedDocument, Types } from "mongoose";

@Schema({ timestamps: true })
export class Message {
    @Prop()
    public id!: Types.ObjectId;

    @Prop()
    public firstName!: string;

    @Prop()
    public lastName!: string;

    @Prop()
    public mailTo!: string;

    @Prop()
    public subject!: string;

    @Prop()
    public message!: string;
    
    @Prop()
    public status!: MessageStatus;

    @Prop()
    public sentAt!: Date;

    @Prop()
    public receivedAt!: Date;

    @Prop()
    public repliedAt!: Date;

    @Prop()
    public repliedBy!: string;
}

export const MessageSchema = SchemaFactory.createForClass(Message);
export type MessageDocument = HydratedDocument<Message>;