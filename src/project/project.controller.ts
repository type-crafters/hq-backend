import { Body, Controller, Delete, Get, HttpException, InternalServerErrorException, NotFoundException, Param, Patch, Post } from "@nestjs/common";
import { ProjectService } from "./project.service";
import { CreateProjectRequest } from "./dto/create-project-request.dto";
import { UpdateProjectRequest } from "./dto/update-project-request.dto";
import { User } from "@/common/decorator/user.decorator";
import { Pag } from "@/common/decorator/pagination.decorator";
import { ErrorResponse } from "@/common/dto/error-response.dto";
import { ListResponse } from "@/common/dto/list-response.dto";
import { ResponseMetadata } from "@/common/dto/response-metadata.dto";
import { ProjectResponse } from "./dto/project-response.dto";
import { ItemResponse } from "@/common/dto/item-response.dto";

@Controller("projects")
export class ProjectController {
    constructor(private readonly projectService: ProjectService) { }

    @Get()
    public async listProjects(@Pag("page") page: number, @Pag("limit") limit: number) {
        try {
            const [projects, skip, lim, total] = await this.projectService.list(page, limit);

            const response = ListResponse.OK();
            const metadata = new ResponseMetadata();

            metadata.limit = lim;
            metadata.offset = skip;
            metadata.total = total;

            response.data = projects.map(ProjectResponse.fromProject);
            response.message = projects.length ? "Project list retrieved successfully." : "Operation completed successfully. No projects found.";
            response.meta = metadata;

            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while retrieving the user list.",
                { cause: error }
            );
        }
    }

    @Get(":id")
    public async getProject(@Param("id") id: string) {
        try {
            const project = (await this.projectService.get(id))
                .orElseThrow(() => new NotFoundException("Project not found."));

            const response = ItemResponse.OK();
            response.message = "Project retrieved successfully.";
            response.data = ProjectResponse.fromProject(project);

            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while retrieving the project.",
                { cause: error }
            );
        }
    }

    @Post()
    public async createProject(@Body() request: CreateProjectRequest, @User("id") id: string) {
        try {
            const projectId = await this.projectService.create(request, id);
            const response = ItemResponse.Created();
            response.message = "Project created.";
            response.data = projectId;
            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while creating the project.",
                { cause: error }
            );
        }
    }

    @Patch(":id")
    public async updateProject(@Param("id") id: string, @Body() request: UpdateProjectRequest) {
        try {
            await this.projectService.update(id, request);
            const response = ItemResponse.OK();
            response.message = "Project updated successfully.";
            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while updating the project.",
                { cause: error }
            );
        }
    }

    @Delete(":id")
    public async deleteProject(@Param("id") id: string) {
        try {
            await this.projectService.delete(id);
            const response = ItemResponse.OK();
            response.message = "Project deleted successfully.";
            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while deleting the project.",
                { cause: error }
            );
        }
    }
}