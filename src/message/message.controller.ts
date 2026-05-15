import { Body, Controller, Get, Param, Patch, Post, Query } from "@nestjs/common";
import { MessageService } from "./message.service";
import type { SendMessageRequest } from "./dto/send-message-request.dto";
import { RequiresPermission } from "@/common/decorator/requires-permission.decorator";
import type { PaginationParams } from "@/common/dto/pagination-params.dto";
import { User } from "@/common/decorator/user.decorator";
import type { ReplyToMessageRequest } from "./dto/reply-to-message-request.dto";

@Controller("messages")
export class MessageController {
    constructor(private readonly messageService: MessageService) { }

    @Get()
    @RequiresPermission("list:message")
    public async listMessages(@Query() params: PaginationParams) {
        return await this.messageService.list(params.page, params.limit);
    }

    @Get(":id")
    @RequiresPermission("list:message")
    public async getMessage(@Param("id") id: string) {
        return await this.messageService.get(id);
    }

    @Post()
    public async sendMessage(@Body() body: SendMessageRequest) {
        await this.messageService.create(body);
    }

    @Patch(":id/read")
    @RequiresPermission("update:message")
    public async setToRead(@Param("id") id: string) {
        await this.messageService.markAsRead(id);
    }

    @Patch(":id/reply")
    @RequiresPermission("update:message")
    public async reply(
        @Param("id") id: string, 
        @Body() body: ReplyToMessageRequest, 
        @User("id") adminId: string
    ) {
        await this.messageService.reply(id, body.reply, adminId);
    }
}