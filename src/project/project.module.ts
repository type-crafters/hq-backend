import { Module } from "@nestjs/common";
import { ProjectController } from "./project.controller";
import { ProjectService } from "./project.service";
import { Project, ProjectSchema } from "./project.schema";
import { FileModule } from "@/file/file.module";
import { MongooseModule } from "@nestjs/mongoose";

@Module({
    imports: [
        MongooseModule.forFeature([{
            name: Project.name,
            schema: ProjectSchema
        }]),
        FileModule
    ],
    controllers: [ProjectController],
    providers: [ProjectService]
})
export class ProjectModule { }