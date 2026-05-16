import { ProjectStatus } from "./dto/project-status.enum";
import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { Types, type HydratedDocument } from "mongoose";

@Schema({ timestamps: true })
export class Project {
    @Prop()
    public _id!: Types.ObjectId;

    @Prop()
    public projectName!: string;

    @Prop()
    public thumbnailUrl!: string;

    @Prop({ type: String, enum: ProjectStatus })
    public status!: ProjectStatus;

    @Prop()
    public description!: string;

    @Prop()
    public content!: string;

    @Prop()
    public tags!: string[];

    @Prop()
    public href!: string;

    @Prop()
    public createdBy!: string;
}

export const ProjectSchema = SchemaFactory.createForClass(Project);
export type ProjectDocument = HydratedDocument<Project>;