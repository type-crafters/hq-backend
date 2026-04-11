import  { Module } from "@nestjs/common";
import  { VerificationTokenService } from "./verification-token.service";
import { TypeOrmModule } from "@nestjs/typeorm";
import { VerificationToken } from "./verification-token.entity";

@Module({
    imports: [TypeOrmModule.forFeature([VerificationToken])],
    providers: [VerificationTokenService],
    exports: [VerificationTokenService]
})
export class VerificationTokenModule { }