import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class Member {
    @Prop()
    public _id!: Types.ObjectId;

    @Prop()
    public firstName!: string;

    @Prop()
    public lastName!: string;

    @Prop()
    public role!: string;

    @Prop()
    public bio!: string;

    @Prop()
    public email!: string;

    @Prop()
    public profilePictureUrl!: string;

    @Prop()
    public since!: number;
}

export const MemberSchema = SchemaFactory.createForClass(Member);
export type MemberDocument = HydratedDocument<Member>;