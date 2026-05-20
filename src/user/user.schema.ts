import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { UserStatus } from "./dto/user-status.enum";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class User {
    public _id!: Types.ObjectId;

    @Prop()
    public firstName!: string;

    @Prop()
    public lastName!: string;

    @Prop({ unique: true })
    public email!: string;

    @Prop()
    public role!: string;

    @Prop()
    public password!: string | null;

    @Prop()
    public profilePictureUrl!: string;

    @Prop({ type: String, enum: UserStatus })
    public status!: UserStatus;

    @Prop()
    public permissions!: string[];

    public createdAt!: Date;
    
    public updatedAt!: Date;
}

export const UserSchema = SchemaFactory.createForClass(User);
export type UserDocument = HydratedDocument<User>;