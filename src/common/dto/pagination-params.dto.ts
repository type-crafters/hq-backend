import { IsInt, IsOptional } from "class-validator";
import { DefaultInt } from "../decorator/default-int.decorator";

export class PaginationParams {
    @IsOptional()
    @IsInt()
    @DefaultInt(1)
    page!: number;

    @IsOptional()
    @IsInt()
    @DefaultInt(10)
    limit!: number;
}