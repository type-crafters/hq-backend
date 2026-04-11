import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { UserModule } from "@/user/user.module";
import { JwtModule } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
import { TypeOrmModule } from "@nestjs/typeorm";
import { RefreshToken } from "./refresh-token.entity";
import { VerificationTokenModule } from "@/verification-token/verification-token.module";
import { MailModule } from "@/mail/mail.module";

@Module({
    imports: [
        UserModule,
        JwtModule.registerAsync({
            global: true,
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                secret: config.getOrThrow("ACCESS_SECRET"),
                signOptions: { expiresIn: 900 }
             })
        }),
        TypeOrmModule.forFeature([RefreshToken]),
        VerificationTokenModule,
        MailModule
    ],
    controllers: [AuthController],
    providers: [AuthService]
})
export class AuthModule { }