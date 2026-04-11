import { Injectable, InternalServerErrorException, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Project } from "./project.entity";
import { MongoRepository } from "typeorm";
import { CreateProjectRequest } from "./dto/create-project-request.dto";
import { UpdateProjectRequest } from "./dto/update-project-request.dto";
import { ObjectId } from "mongodb";

@Injectable()
export class ProjectService {
    constructor(@InjectRepository(Project) private readonly projectRepository: MongoRepository<Project>) { }

    public async list(page: number, limit: number): Promise<Array<Project>> {
        try {
            return await this.projectRepository.find({
                skip: limit * (page - 1),
                take: limit,
                order: { createdAt: -1 }
            });
        } catch {
            throw new InternalServerErrorException("Failed to fetch project list.");
        }
    }

    public async get(id: string): Promise<Project> {
        const notFound = new NotFoundException("Project '" + id + "' not found.");
        if (!ObjectId.isValid(id)) throw notFound;

        const project = await this.projectRepository.findOneBy({ _id: new ObjectId(id) });
        if (project == null) throw notFound;

        return project;
    }

    public async create(request: CreateProjectRequest, userId: string): Promise<Project> {
        const project: Project = this.projectRepository.create({
            ...request,
            thumbnailUrl: request.thumbnailUrl ?? "", // TODO get a default link from file service
            content: request.content ?? "",
            tags: request.tags ?? [],
            createdBy: userId
        });

        return await this.projectRepository.save(project);
    }

    public async update(id: string, request: UpdateProjectRequest): Promise<void> {
        const notFound = new NotFoundException("Project '" + id + "' not found.");
        if (!ObjectId.isValid(id)) throw notFound;

        const patch = Object.fromEntries(
            Object.entries(request).filter(([_, v]) => v != null)
        );

        if (Object.keys(patch).length === 0) return;

        try {
            const result = await this.projectRepository.updateOne(
                { _id: new ObjectId(id) },
                { $set: patch }
            );

            if (result.matchedCount === 0) throw notFound;
        } catch {
            throw new InternalServerErrorException("Failed to update project.");
        }
    }

    public async delete(id: string): Promise<void> {
        const notFound = new NotFoundException("Project '" + id + "' not found.");
        if (!ObjectId.isValid(id)) throw notFound;

        try {
            const result = await this.projectRepository.deleteOne({ _id: new ObjectId(id) });

            if (result.deletedCount === 0) throw notFound;
        } catch {
            throw new InternalServerErrorException("Failed to delete project.");
        }
    }
}