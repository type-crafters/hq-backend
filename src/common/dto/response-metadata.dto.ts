import { IsInt, IsOptional } from "class-validator";

export class ResponseMetadata {
    @IsOptional()
    @IsInt()
    public offset?: number;

    @IsOptional()
    @IsInt()
    public limit?: number;

    @IsOptional()
    @IsInt()
    public total?: number;
}