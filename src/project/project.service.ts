import { Injectable, InternalServerErrorException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model, Types } from "mongoose";
import { Project, type ProjectDocument } from "./project.schema";
import { CreateProjectRequest } from "./dto/create-project-request.dto";
import { UpdateProjectRequest } from "./dto/update-project-request.dto";
import { FileService } from "@/file/file.service";
import { Optional } from "@/common/class/optional";

@Injectable()
export class ProjectService {
    constructor(
        @InjectModel(Project.name) private readonly projectModel: Model<ProjectDocument>,
        private readonly fileService: FileService
    ) { }

    public async list(page: number, limit: number): Promise<ProjectDocument[]> {
        const maxLimit = 24;

        const clamp = Math.min(limit, maxLimit);

        try {
            const projects = await this.projectModel
                .find()
                .sort({ createdAt: "desc" })
                .skip(clamp * (page - 1))
                .limit(clamp)
                .exec();

            return await Promise.all(
                projects.map(async (p) => {
                    p.thumbnailUrl = await this.fileService.getSignedUrl(
                        p.thumbnailUrl
                    );
                    return p;
                })
            );
        } catch {
            throw new InternalServerErrorException("Failed to fetch project list.");
        }
    }

    public async get(
        id: string
    ): Promise<Optional<ProjectDocument>> {

        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        const project = await this.projectModel
            .findById(id)
            .exec();

        if (!project) {
            return Optional.empty();
        }

        project.thumbnailUrl = await this.fileService.getSignedUrl(project.thumbnailUrl);

        return Optional.of(project);
    }

    public async create(request: CreateProjectRequest, userId: string): Promise<ProjectDocument> {
        return await this.projectModel.create({
            ...request,
            thumbnailUrl: request.thumbnailUrl ?? this.fileService.placeholder,
            content: request.content ?? "",
            tags: request.tags ?? [],
            createdBy: userId
        });
    }

    public async update(id: string, request: UpdateProjectRequest): Promise<Optional<ProjectDocument>> {
        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        const patch = Object.fromEntries(
            Object.entries(request)
                .filter(([_, value]) => value != null)
        );

        if (Object.keys(patch).length === 0) {
            return this.get(id);
        }

        try {
            const project = await this.projectModel.findById(id);

            if (!project) {
                return Optional.empty();
            }

            Object.assign(project, patch);

            const saved = await project.save();

            return Optional.of(saved);
        } catch {
            throw new InternalServerErrorException("Failed to update project.");
        }
    }

    public async delete(id: string): Promise<Optional<ProjectDocument>> {
        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        try {
            const project = await this.projectModel.findByIdAndDelete(id).exec();

            if (!project) {
                return Optional.empty();
            }

            return Optional.of(project);
        } catch {
            throw new InternalServerErrorException("Failed to delete project.");
        }
    }
}

