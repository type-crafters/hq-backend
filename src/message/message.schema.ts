import { MessageStatus } from "./dto/message-status.enum";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class Message {
    @Prop()
    public _id!: Types.ObjectId;

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
    
    @Prop({ type: String, enum: MessageStatus })
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