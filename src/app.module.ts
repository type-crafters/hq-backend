import { Module } from "@nestjs/common";
import { ProjectModule } from "./project/project.module";
import { MemberModule } from "./member/member.module";
import { MessageModule } from "./message/message.module";
import { AuthModule } from "./auth/auth.module";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { UserModule } from "./user/user.module";
import { AppController } from "./app.controller";
import { MongooseModule } from "@nestjs/mongoose";

@Module({
    imports: [
        ConfigModule.forRoot({ isGlobal: true }),
        MongooseModule.forRootAsync({
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                uri: `mongodb://${config.getOrThrow("MONGO_HOST")}:${config.getOrThrow("MONGO_PORT")}/${config.getOrThrow("MONGO_NAME")}`
            })
        }),
        MemberModule,
        MessageModule,
        AuthModule,
        ProjectModule,
        UserModule
    ],
    controllers: [AppController]
})
export class AppModule { }