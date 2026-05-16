
import { TokenType } from "./dto/token-type.enum";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class VerificationToken {
    @Prop()
    public _id!: Types.ObjectId;

    @Prop({ unique: true })
    public hash!: string;

    @Prop()
    public uid!: string;

    @Prop({ type: String, enum: TokenType })
    public type!: TokenType;

    @Prop({ expires: 0 })
    public expiresAt!: Date;
}

export const VerificationTokenSchema = SchemaFactory.createForClass(VerificationToken);
export type VerificationTokenDocument = HydratedDocument<VerificationToken>;