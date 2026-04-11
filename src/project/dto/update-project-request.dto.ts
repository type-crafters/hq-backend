import { IsArray, IsEnum, IsOptional, IsString, IsUrl } from "class-validator";
import { ProjectStatus } from "./project-status.enum";

export class UpdateProjectRequest {
    @IsOptional()
    @IsString()
    public projectName?: string;

    @IsOptional()
    @IsUrl()
    public thumbnailUrl?: string;

    @IsOptional()
    @IsEnum(ProjectStatus)
    public status?: ProjectStatus;

    @IsOptional()
    @IsString()
    public description?: string;

    @IsOptional()
    @IsString()
    public content?: string;

    @IsOptional()
    @IsArray()
    @IsString({ each: true })
    public tags?: string[];

    @IsOptional()
    @IsUrl()
    public href?: string;
}