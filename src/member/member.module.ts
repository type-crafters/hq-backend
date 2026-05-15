import { Module } from "@nestjs/common";
import { MemberController } from "./member.controller";
import { MemberService } from "./member.service";
import { Member, MemberSchema } from "./member.schema";
import { FileModule } from "@/file/file.module";
import { MongooseModule } from "@nestjs/mongoose";

@Module({
    imports: [
        MongooseModule.forFeature([{
            name: Member.name,
            schema: MemberSchema
        }]),
        FileModule
    ],
    controllers: [MemberController],
    providers: [MemberService]
})
export class MemberModule { }