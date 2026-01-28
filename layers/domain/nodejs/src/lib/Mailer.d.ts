import type { Transporter, SentMessageInfo } from "nodemailer";
import type { Options } from "nodemailer/lib/smtp-transport";
import type { RequiresEnvironment } from "./RequiresEnvironment";
import type { User } from "../model/User";
import { Async, Consumer } from "../types";

export declare class Mailer extends RequiresEnvironment {
    private static VIEW_DIR: string;
    
    constructor();

    public get transporter(): Transporter<SentMessageInfo, Options>;

    public sendVerificationEmail: Async<Consumer<User>>;
    public sendPasswordResetEmail: Async<Consumer<User>>;
}