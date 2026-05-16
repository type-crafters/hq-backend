import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { UserStatus } from "./dto/user-status.enum";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class User {
    @Prop()
    public id!: Types.ObjectId;

    @Prop()
    public firstName!: string;

    @Prop()
    public lastName!: string;

    @Prop({ unique: true })
    public email!: string;

    @Prop()
    public password!: string;

    @Prop()
    public profilePictureUrl!: string;

    @Prop({ type: String, enum: UserStatus })
    public status!: UserStatus;

    @Prop()
    public permissions!: string[];
}

export const UserSchema = SchemaFactory.createForClass(User);
export type UserDocument = HydratedDocument<User>;