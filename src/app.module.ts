import { Module } from "@nestjs/common";
import { PostModule } from "./post/post.module";
import { ProjectModule } from "./project/project.module";
import { MemberModule } from "./member/member.module";
import { MessageModule } from "./message/message.module";
import { AuthModule } from "./auth/auth.module";
import { TypeOrmModule } from "@nestjs/typeorm";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { UserModule } from "./user/user.module";

@Module({
    imports: [
        ConfigModule.forRoot({ isGlobal: true }),
        TypeOrmModule.forRootAsync({
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                type: "mongodb",
                host: config.getOrThrow("MONGO_HOST"),
                port: parseInt(config.getOrThrow("MONGO_PORT")) || 27017,
                database: config.getOrThrow("MONGO_NAME"),
                entities: [import.meta.dirname + "/**/*.entity.{ts,js}"],
                logging: true
            })
        }),
        MemberModule,
        MessageModule,
        PostModule,
        AuthModule,
        ProjectModule,
        UserModule
    ]
})
export class AppModule { }