import type { Project } from "../project.schema";
import type { ProjectStatus } from "./project-status.enum";

interface ProjectResponseArgs {
    id: string;
    projectName: string;
    thumbnailUrl: string;
    status: ProjectStatus;
    description: string;
    content: string;
    tags: string[];
    href: string;
    createdBy: string;
    createdAt: Date;
    updatedAt: Date;
}

export class ProjectResponse {
    public id!: string;
    public projectName!: string;
    public thumbnailUrl!: string;
    public status!: ProjectStatus;
    public description!: string;
    public content!: string;
    public tags!: string[];
    public href!: string;
    public createdBy!: string;
    public createdAt!: Date;
    public updatedAt!: Date;

    private constructor({
        id,
        projectName,
        thumbnailUrl,
        status,
        description,
        content,
        tags,
        href,
        createdBy,
        createdAt,
        updatedAt
    }: ProjectResponseArgs) {
        this.id = id;
        this.projectName = projectName;
        this.thumbnailUrl = thumbnailUrl;
        this.status = status;
        this.description = description;
        this.content = content;
        this.tags = tags;
        this.href = href;
        this.createdBy = createdBy;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public static fromProject(project: Project): ProjectResponse {
        return new ProjectResponse({
            id: project._id.toString(),
            projectName: project.projectName,
            thumbnailUrl: project.thumbnailUrl,
            status: project.status,
            description: project.description,
            content: project.content,
            tags: project.tags,
            href: project.href,
            createdBy: project.createdBy.toString(),
            createdAt: project.createdAt,
            updatedAt: project.updatedAt,
        });
    }
}