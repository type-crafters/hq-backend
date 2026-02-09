import { createTransport, type Transporter } from "nodemailer";
import type { SentMessageInfo, Options } from "nodemailer/lib/smtp-transport/index.js";
import { RequiresEnvironment } from "../util/RequiresEnvironment.js";

export class Mailer extends RequiresEnvironment {
    protected override required: Set<string> = new Set([
        "SMTP_SERVICE", 
        "SMTP_USER",
        "SMTP_PASS",
        "SMTP_FROM"
    ]);

    private transporter: Transporter<SentMessageInfo, Options>;

    private get from() {
        return `${this.getEnv("SMTP_FROM").toString()} <${this.getEnv("SMTP_USER").toString()}>`;
    }

    constructor(environment: NodeJS.ProcessEnv) {
        super(environment);
        this.transporter = createTransport({
            service: this.getEnv("SMTP_SERVICE").toString(),
            auth: {
                user: this.getEnv("SMTP_USER").toString(),
                pass: this.getEnv("SMTP_PASS").toString()
            }
        });
    }

    public async sendHTMLEmail(to: string, html: string, subject: string) {
        return await this.transporter.sendMail({
            subject,
            html,
            to,
            from: this.from
        });
    }

    public async sendTextEmail(to: string, content: string, subject: string) {
        return await this.transporter.sendMail({
            subject,
            text: content,
            to,
            from: this.from
        });
    }
}