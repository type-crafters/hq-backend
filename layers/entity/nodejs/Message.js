export class Message {
    /** @type {import("crypto").UUID} */
    id;
    /** @type {string} */
    senderName;
    /** @type {string} */
    senderEmail;
    /** @type {string} */
    subject;
    /** @type {string} */
    message;
    /** @type {Date} */
    sendDate;

    /**
     * @param {{
     *  id: string,
     *  senderName: string,
     *  subject: string,
     *  message: string,
     *  sendDate: string,
     *  args: any
     * }} params
     */
    constructor({
        id,
        senderName,
        senderEmail,
        subject,
        message,
        sendDate,
        ...args
    } = {}) {
        this.id = id;
        this.senderName = senderName;
        this.subject = subject;
        this.message = message;
        this.sendDate = new Date(sendDate);
        void args;
    }
}