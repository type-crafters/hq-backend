import { createParamDecorator, ExecutionContext } from "@nestjs/common";
import { Request } from "express";

type TokenField = "id" | "email" | "permissions"

export const User = createParamDecorator((field: TokenField | undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<Request>();
    const user = request["user"];

    if (field) return user?.[field];
    
    return user;
});