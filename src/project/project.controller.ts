import { Body, Controller, Delete, Get, Param, Patch, Post, Query } from "@nestjs/common";
import { ProjectService } from "./project.service";
import { CreateProjectRequest } from "./dto/create-project-request.dto";
import { UpdateProjectRequest } from "./dto/update-project-request.dto";
import { User } from "@/common/decorator/user.decorator";
import { RequiresPermission } from "@/common/decorator/requires-permission.decorator";
import type { PaginationParams } from "@/common/dto/pagination-params.dto";

@Controller("projects")
export class ProjectController {
    constructor(private readonly projectService: ProjectService) { }

    @Get()
    public async listProjects(@Query() params: PaginationParams) {
        return await this.projectService.list(params.page, params.limit);
    }

    @Get(":id")
    public async getProject(@Param("id") id: string) {
        return await this.projectService.get(id);
    }

    @Post()
    @RequiresPermission("create:project")
    public async createProject(@Body() request: CreateProjectRequest, @User("id") id: string) {
        await this.projectService.create(request, id);
    }

    @Patch(":id")
    @RequiresPermission("update:project")
    public async updateProject(@Param("id") id: string, @Body() request: UpdateProjectRequest) {
        await this.projectService.update(id, request);
    }

    @Delete(":id")
    @RequiresPermission("delete:project")
    public async deleteProject(@Param("id") id: string) {
        await this.projectService.delete(id);
    }
}