import  { Module } from "@nestjs/common";
import  { MailService } from "./mail.service";
import { TransporterProvider } from "./transporter.provider";

@Module({
    imports: [],
    controllers: [],
    providers: [MailService, TransporterProvider],
    exports: [MailService]
})
export class MailModule { }
