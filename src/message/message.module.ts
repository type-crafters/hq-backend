import { Module } from "@nestjs/common";
import { MessageController } from "./message.controller";
import { MessageService } from "./message.service";
import { MailModule } from "@/mail/mail.module";
import { MongooseModule } from "@nestjs/mongoose";
import { Message, MessageSchema } from "./message.schema";

@Module({
    imports: [
        MongooseModule.forFeature([{
            name: Message.name,
            schema: MessageSchema
        }]), 
        MailModule
    ],
    controllers: [MessageController],
    providers: [MessageService]
})
export class MessageModule { }