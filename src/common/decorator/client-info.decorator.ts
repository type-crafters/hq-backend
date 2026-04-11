import { createParamDecorator, ExecutionContext } from "@nestjs/common";

type ClientInfoType = "ipAddress" | "userAgent";

export const ClientInfo = createParamDecorator((data: ClientInfoType | undefined, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest();

    const ipAddress =
      req.ip ||
      req.headers['x-forwarded-for']?.toString().split(',')[0] ||
      req.socket?.remoteAddress;

    const userAgent = req.headers['user-agent'] ?? '';

    const client: Record<ClientInfoType, string> = { ipAddress, userAgent };

    return data ? client[data] : client;
});