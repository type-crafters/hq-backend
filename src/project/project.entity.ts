import { ObjectId } from "mongodb";
import { Column, CreateDateColumn, Entity, ObjectIdColumn, UpdateDateColumn } from "typeorm";
import { ProjectStatus } from "./dto/project-status.enum";

@Entity("projects")
export class Project {
    @ObjectIdColumn()
    public id!: ObjectId;

    @Column()
    public projectName!: string;

    @Column()
    public thumbnailUrl!: string;

    @Column()
    public status!: ProjectStatus;

    @Column()
    public description!: string;

    @Column()
    public content!: string;

    @Column()
    public tags!: string[];

    @Column()
    public href!: string;

    @Column()
    public createdBy!: string;

    @Column()
    @CreateDateColumn()
    public createdAt!: Date;

    @Column()
    @UpdateDateColumn()
    public updatedAt!: Date;
}