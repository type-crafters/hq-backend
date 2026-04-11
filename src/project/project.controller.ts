import { Body, Controller, Delete, Get, Param, ParseIntPipe, Patch, Post, Query, UnauthorizedException, UseGuards } from "@nestjs/common";
import { ProjectService } from "./project.service";
import { CreateProjectRequest } from "./dto/create-project-request.dto";
import { UpdateProjectRequest } from "./dto/update-project-request.dto";
import { User } from "@/common/decorator/user.decorator";
import { ProtectedRoute } from "@/auth/protected-route.guard";

@Controller("project")
export class ProjectController {
    constructor(private readonly projectService: ProjectService) { }

    @Get()
    public listProjects(@Query("page", ParseIntPipe) page: number, @Query("limit", ParseIntPipe) limit: number) {

    }

    @Get(":id")
    public getProject(@Param("id") id: string) {

    }

    @Post()
    @UseGuards(ProtectedRoute)
    public createProject(@Body() request: CreateProjectRequest, @User("id") id: string, @User("permissions") permissions: string[]) {
        if (!permissions.includes("create:project")) throw new UnauthorizedException("Unauthorized.");
        const project = this.projectService.create(request, id);
    }

    @Patch(":id")
    @UseGuards(ProtectedRoute)
    public updateProject(@Param("id") id: string, @Body() request: UpdateProjectRequest) {

    }

    @Delete(":id")
    @UseGuards(ProtectedRoute)
    public deleteProject(@Param("id") id: string) {

    }
}