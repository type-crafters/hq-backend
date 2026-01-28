export class VerificationToken {
    static #EMAIL_EXPIRY = 86_400 * 1_000;
    static #PASSWORD_EXPIRY = 3_600 * 1_000;
    static VERIFY_EMAIL = "VERIFY_EMAIL";
    static RESET_PASSWORD = "RESET_PASSWORD";

    hash;
    type;
    ttl;

    constructor({
        hash,
        type,
        ttl
    }) {
        this.hash = hash;
        this.type = type;
        this.ttl = ttl;
    }

    toItem() {
        return {
            hash: this.hash,
            type: this.type,
            ttl: Math.floor(this.ttl.getTime() / 1000)
        }
    }

    static forEmailVerification(hash) {
        return new VerificationToken({
            hash,
            type: this.VERIFY_EMAIL,
            ttl: new Date(Date.now() + this.#EMAIL_EXPIRY)
        })
    }

    static forPasswordReset(hash) {
        return new VerificationToken({
            hash,
            type: this.RESET_PASSWORD,
            ttl: new Date(Date.now() + this.#PASSWORD_EXPIRY)
        }) 
    }
}