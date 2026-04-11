import { type Provider } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createTransport, type Transporter } from "nodemailer";

export const TransporterProvider: Provider<Transporter> = {
    provide: "TRANSPORTER",
    inject: [ConfigService],
    useFactory: (config: ConfigService): Transporter => {
        return createTransport({
            service: config.getOrThrow("SMTP_SERVICE"),
            port: parseInt(config.getOrThrow("SMTP_PORT")) || 587,
            auth: {
                user: config.getOrThrow("SMTP_USER"),
                pass: config.getOrThrow("SMTP_PASS")
            }
        });
    }
}
