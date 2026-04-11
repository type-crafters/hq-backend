import { ObjectId } from "mongodb";
import { Column, Entity, Index, ObjectIdColumn } from "typeorm";
import { TokenType } from "./token-type.enum";

@Entity("verificationTokens")
export class VerificationToken {
    @ObjectIdColumn()
    public id!: ObjectId;

    @Index({ unique: true })
    @Column()
    public hash!: string;

    @Column()
    public sub!: string;

    @Column()
    public type!: TokenType;

    @Index({ expireAfterSeconds: 0 })
    @Column()
    public expiresAt!: Date;
}