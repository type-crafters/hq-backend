import { Inject, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { type Transporter } from "nodemailer";
import * as ejs from "ejs";
import { TRANSPORTER } from "./constants";
import path from "node:path";

@Injectable()
export class MailService {
    private readonly from: string;

    constructor(
        @Inject(TRANSPORTER) private readonly transporter: Transporter,
        config: ConfigService,
    ) {
        this.from = config.getOrThrow("SMTP_FROM");
    }

    private get mailTemplateDirectory() {
        return path.resolve(path.join(import.meta.dirname), "..", "common", "template");
    }

    public async sendText(to: string, subject: string, body: string): Promise<void> {
        await this.transporter.sendMail({
            from: this.from,
            to,
            subject,
            text: body,
        });
    }

    public async sendHtml(to: string, subject: string, html: string): Promise<void> {
        await this.transporter.sendMail({
            from: this.from,
            to,
            subject,
            html,
        });
    }

    public async renderAndSend(
        to: string,
        subject: string,
        filename: string,
        data: Record<string, any>,
    ): Promise<void> {
        const html = await ejs.renderFile(path.join(this.mailTemplateDirectory, filename), data, { async: true });

        await this.sendHtml(to, subject, html);
    }
}