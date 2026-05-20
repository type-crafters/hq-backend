import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class Session {
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
    
    public createdAt!: Date;
    
    public updatedAt!: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);
export type SessionDocument = HydratedDocument<Session>;