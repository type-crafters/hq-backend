import { type CanActivate, type ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { type Request } from "express";
import { JwtService } from "@nestjs/jwt";
import { type AccessClaims } from "@/common/interface/access-claims.interface";

declare global {
    namespace Express {
        interface Request {
            user?: AccessClaims;
        }
    }
}

@Injectable()
export class ProtectedRoute implements CanActivate {
    constructor(private jwtService: JwtService) { }

    public async canActivate(context: ExecutionContext): Promise<boolean> {
        const unauthorized = new UnauthorizedException("Unauthorized.");
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

        return true;
    }
}