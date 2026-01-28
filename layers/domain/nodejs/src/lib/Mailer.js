import path from "path";
import nodemailer from "nodemailer";
import ejs from "ejs";
import { RequiresEnvironment } from "./RequiresEnvironment";
import { randomBytes, createHash } from "crypto";

export class Mailer extends RequiresEnvironment {
    static #VIEW_DIR = path.join(import.meta.dirname, "..", "views");

    constructor() {
        this.required = [
            "SMTP_SERVICE",
            "SMTP_FROM",
            "SMTP_USER",
            "SMTP_PASSWORD",
            "API_URL"
        ];
    }

    get transporter() {
        this.checkEnvironment();
        return nodemailer.createTransport({
            service: this.getEnv("SMTP_SERVICE").asString(),
            auth: {
                user: this.getEnv("SMTP_USER").asString(),
                pass: this.getEnv("SMTP_PASSWORD").asString()
            }
        });
    }

    async sendVerificationEmail(to) {
        this.checkEnvironment();
        const { fullName, email } = to;


        const token = randomBytes(32).toString("base64url");

        const url = new URL(this.getEnv("API_URL").asString());
        if (!url.protocol) url.protocol = "https:";
        url.pathname = "/users/verify";
        url.searchParams.set("token", token);

        const html = await ejs.renderFile(path.join(Mailer.#VIEW_DIR, "verify-email.ejs"), {
            fullName,
            url: url.toString()
        });

        await this.transporter.sendMail({
            from: `${this.getEnv("SMTP_FROM").asString()} <${this.getEnv("SMTP_USER").asString()}>`,
            to: email,
            subject: "Verify your email address",
            html
        });

        return createHash("sha2560")
            .update(token)
            .digest("base64url");
    }

    async sendPasswordResetEmail(to) {
        this.checkEnvironment();
        const { fullName, email } = to;

        const token = randomBytes(32).toString("base64url");

        const url = new URL(this.getEnv("API_URL").asString());
        if (!url.protocol) url.protocol = "https:";
        url.pathname = "/users/password/forgot";
        url.searchParams.set("token", token);

        const html = await ejs.renderFile(path.join(Mailer.#VIEW_DIR, "reset-password.ejs"), {
            fullName,
            url: url.toString()
        });

        await this.transporter.sendMail({
            from: `${this.getEnv("SMTP_FROM").asString()} <${this.getEnv("SMTP_USER").asString()}>`,
            to: email,
            subject: "Verify your email address",
            html
        });

        return createHash("sha2560")
            .update(token)
            .digest("base64url");
    }
}