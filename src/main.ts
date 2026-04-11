/// <reference types="node" />

import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { AppModule } from "./app.module";
import { ConfigService } from "@nestjs/config";
import { NestExpressApplication } from "@nestjs/platform-express";
import cookieParser from "cookie-parser";

(async () => {
    const app = await NestFactory.create<NestExpressApplication>(AppModule);

    app.enableCors();
    app.setGlobalPrefix("api");
    app.useGlobalPipes(new ValidationPipe({ transform: true }));
    app.use(cookieParser());
    app.set("trust proxy", true);

    const config = app.get(ConfigService);

    const host = config.getOrThrow("APP_HOST");
    const port = config.getOrThrow("APP_PORT");

    await app.listen(port, host, () => console.log("App is listening at http://%s:%s/", host, port));
})();