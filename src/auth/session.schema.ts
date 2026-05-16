import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class Session {
    @Prop()
    public _id!: Types.ObjectId;

    @Prop({ unique: true })
    public jssessid!: string;

    @Prop()
    public uid!: Types.ObjectId;

    @Prop()
    public ipAddress!: string;

    @Prop()
    public userAgent!: string;

    @Prop()
    public expiresAt!: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);
export type SessionDocument = HydratedDocument<Session>;