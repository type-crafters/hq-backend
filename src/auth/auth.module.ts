import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { UserModule } from "@/user/user.module";
import { VerificationTokenModule } from "@/verification-token/verification-token.module";
import { MailModule } from "@/mail/mail.module";
import { MongooseModule } from "@nestjs/mongoose";
import { Session, SessionSchema } from "./session.schema";

@Module({
    imports: [
        MongooseModule.forFeature([{
            name: Session.name,
            schema: SessionSchema
        }]),
        UserModule,
        VerificationTokenModule,
        MailModule
    ],
    controllers: [AuthController],
    providers: [AuthService]
})
export class AuthModule { }