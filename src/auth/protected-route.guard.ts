import { type CanActivate, type ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from "@nestjs/common";
import { type Request } from "express";
import { JwtService } from "@nestjs/jwt";
import { type AccessClaims } from "@/common/interface/access-claims.interface";
import { Reflector } from "@nestjs/core";
import { PERMISSION_KEY } from "@/common/decorator/requires-permission.decorator";

declare global {
    namespace Express {
        interface Request {
            user?: AccessClaims;
        }
    }
}

@Injectable()
export class ProtectedRoute implements CanActivate {
    constructor(private readonly jwtService: JwtService, private readonly reflector: Reflector) { }

    public async canActivate(context: ExecutionContext): Promise<boolean> {
        const unauthorized = new UnauthorizedException("Authentication failed.");
        const forbidden = new ForbiddenException("User is not authorized to perform this operation.");

        const request = context.switchToHttp().getRequest<Request>();
        const [type, token] = request.headers.authorization?.split(" ") ?? [];

        if (!type || type.trim().toLowerCase() !== "bearer") throw unauthorized;
        if (!token) throw unauthorized;

        try {
            const payload = await this.jwtService.verifyAsync<AccessClaims>(token);
            request["user"] = payload;
        } catch {
            throw unauthorized;
        }

        const requiredPermission = this.reflector.getAllAndOverride<string>(PERMISSION_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (!requiredPermission) return true;

        if (!request.user!.permissions.includes(requiredPermission)) {
            throw forbidden;
        }

        return true;
    }
}