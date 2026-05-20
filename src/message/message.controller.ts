import { Body, Controller, Get, HttpException, InternalServerErrorException, NotFoundException, Param, Patch, Post } from "@nestjs/common";
import { MessageService } from "./message.service";
import type { SendMessageRequest } from "./dto/send-message-request.dto";
import { User } from "@/common/decorator/user.decorator";
import type { ReplyToMessageRequest } from "./dto/reply-to-message-request.dto";
import { Pag } from "@/common/decorator/pagination.decorator";
import { ListResponse } from "@/common/dto/list-response.dto";
import { ResponseMetadata } from "@/common/dto/response-metadata.dto";
import { ItemResponse } from "@/common/dto/item-response.dto";
import { ErrorResponse } from "@/common/dto/error-response.dto";

@Controller("messages")
export class MessageController {
    constructor(private readonly messageService: MessageService) { }

    @Get()
    public async listMessages(@Pag("page") page: number, @Pag("limit") limit: number) {
        try {
            const [messages, skip, lim, total] = await this.messageService.list(page, limit);

            if (!messages.length) {
                const error = new ErrorResponse();
                error.status = 404;
                error.message = "No messages were found.";
                error.error = "Not found";
                return error;
            }

            const response = new ListResponse();
            const metadata = new ResponseMetadata();

            metadata.limit = lim;
            metadata.offset = skip;
            metadata.total = total;

            response.data = messages;
            response.message = "Message list retrieved successfully.";
            response.status = 200;
            response.meta = metadata;

            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while retrieving the message list.",
                { cause: error }
            );
        }
    }

    @Get(":id")
    public async getMessage(@Param("id") id: string) {
        try {
            const message = (await this.messageService.get(id))
                .orElseThrow(() => new NotFoundException("Message not found."));

            const response = ItemResponse.OK();
            response.message = "Message retrieved successfully.";
            response.data = message;

            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while retrieving the message.",
                { cause: error }
            );
        }
    }

    @Post()
    public async sendMessage(@Body() body: SendMessageRequest) {
        try {
            const messageId = await this.messageService.create(body);
            const response = ItemResponse.Created();
            response.message = "Message created.";
            response.data = messageId;
            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while creating the message.",
                { cause: error }
            );
        }
    }

    @Patch(":id/read")
    public async setToRead(@Param("id") id: string) {
        try {
            await this.messageService.markAsRead(id);
            const response = ItemResponse.OK();
            response.message = "Message marked as read successfully.";
            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while marking the message as read.",
                { cause: error }
            );
        }
    }

    @Patch(":id/reply")
    public async reply(
        @Param("id") id: string, 
        @Body() body: ReplyToMessageRequest, 
        @User("id") adminId: string
    ) {
        try {
            await this.messageService.reply(id, body.reply, adminId);
            const response = ItemResponse.OK();
            response.message = "Message replied successfully.";
            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while replying to the message.",
                { cause: error }
            );
        }
    }
}