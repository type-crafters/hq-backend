import  { Module } from "@nestjs/common";
import  { VerificationTokenService } from "./verification-token.service";
import { MongooseModule } from "@nestjs/mongoose";
import { VerificationToken, VerificationTokenSchema } from "./verification-token.schema";

@Module({
    imports: [MongooseModule.forFeature([{ 
        name: VerificationToken.name, 
        schema: VerificationTokenSchema 
    }])],
    providers: [VerificationTokenService],
    exports: [VerificationTokenService]
})
export class VerificationTokenModule { }