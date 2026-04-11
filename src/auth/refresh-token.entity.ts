import { ObjectId } from "mongodb";
import { Column, CreateDateColumn, Entity, Index, ObjectIdColumn } from "typeorm";

@Entity("refreshTokens")
export class RefreshToken {
    @ObjectIdColumn()
    public id!: ObjectId;

    @Index({ unique: true })
    @Column()
    public jti!: string;

    @Column()
    public sub!: string;

    @CreateDateColumn()
    public createdAt!: Date;

    @Column()
    public expiresAt!: Date;

    @Column()
    public userAgent!: string;

    @Column()
    public ipAddress!: string;
} 