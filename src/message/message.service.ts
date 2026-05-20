import {
    Injectable,
    InternalServerErrorException
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model, Types } from "mongoose";
import { Message, type MessageDocument } from "./message.schema";
import { SendMessageRequest } from "./dto/send-message-request.dto";
import { MessageStatus } from "./dto/message-status.enum";
import { MailService } from "@/mail/mail.service";
import { Optional } from "@/common/class/optional";

@Injectable()
export class MessageService {
    constructor(
        @InjectModel(Message.name) private readonly messageModel: Model<MessageDocument>,
        private readonly mailService: MailService
    ) { }

    public async create(request: SendMessageRequest): Promise<MessageDocument> {
        return await this.messageModel.create({
            ...request,
            status: MessageStatus.Received,
            sentAt: new Date(request.sentAt),
            receivedAt: new Date()
        });
    }

    public async list(page: number, limit: number): Promise<[Array<MessageDocument>, number, number, number]> {
        const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
        const safeLimit = Number.isFinite(limit) ? Math.floor(limit) : 10;
        const clampedLimit = Math.min(48, Math.max(1, safeLimit));
        const skip = (safePage - 1) * clampedLimit;

        try {
            const [result, total] = await Promise.all([
                this.messageModel
                    .find()
                    .sort({ sentAt: -1 })
                    .skip(skip)
                    .limit(clampedLimit)
                    .exec(),
                this.messageModel.countDocuments().exec(),
            ]);

            return [result, skip, clampedLimit, total];
        } catch {
            throw new InternalServerErrorException(
                "Failed to fetch message list."
            );
        }
    }

    public async get(id: string): Promise<Optional<MessageDocument>> {
        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        const message = await this.messageModel
            .findById(id)
            .exec();

        if (!message) {
            return Optional.empty();
        }

        return Optional.of(message);
    }

    public async markAsRead(id: string): Promise<Optional<MessageDocument>> {
        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        try {
            const message =
                await this.messageModel.findById(id);

            if (!message) {
                return Optional.empty();
            }

            message.status = MessageStatus.Read;

            const saved = await message.save();

            return Optional.of(saved);
        } catch {
            throw new InternalServerErrorException(
                "Failed to mark message as read."
            );
        }
    }

    public async reply(
        id: string,
        reply: string,
        adminId: string
    ): Promise<Optional<MessageDocument>> {
        const optionalMessage = await this.get(id);

        if (!optionalMessage.isPresent()) {
            return Optional.empty();
        }

        const message = optionalMessage.get();

        try {
            await this.mailService.sendText(
                message.mailTo,
                "Your inquiry @ TypeCraftersHQ",
                reply
            );

            message.status = MessageStatus.Replied;

            message.repliedAt = new Date();

            message.repliedBy = adminId;

            const saved = await message.save();

            return Optional.of(saved);
        } catch {
            throw new InternalServerErrorException(
                "Failed to reply to message."
            );
        }
    }

}

