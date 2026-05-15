
import { TokenType } from "./dto/token-type.enum";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import type { HydratedDocument, Types } from "mongoose";

@Schema({ timestamps: true })
export class VerificationToken {
    @Prop()
    public id!: Types.ObjectId;

    @Prop({ unique: true })
    public hash!: string;

    @Prop()
    public uid!: string;

    @Prop()
    public type!: TokenType;

    @Prop({ expires: 0 })
    public expiresAt!: Date;
}

export const VerificationTokenSchema = SchemaFactory.createForClass(VerificationToken);
export type VerificationTokenDocument = HydratedDocument<VerificationToken>;