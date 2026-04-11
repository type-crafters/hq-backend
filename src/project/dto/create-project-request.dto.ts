import { IsArray, IsEnum, IsNotEmpty, IsOptional, IsString, IsUrl } from "class-validator";
import { ProjectStatus } from "./project-status.enum";

export class CreateProjectRequest {
  @IsString()
  @IsNotEmpty()
  public projectName!: string;

  @IsOptional()
  @IsUrl()
  public thumbnailUrl?: string;

  @IsEnum(ProjectStatus)
  public status!: ProjectStatus;

  @IsString()
  @IsNotEmpty()
  public description!: string;

  @IsOptional()
  @IsString()
  public content?: string;

  @IsArray()
  @IsString({ each: true })
  public tags!: string[];

  @IsUrl()
  public href!: string;
}