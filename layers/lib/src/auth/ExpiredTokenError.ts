export interface ExpiredTokenErrorOptions {
    cause?: unknown;
}

export class ExpiredTokenError extends Error {
    constructor()
    constructor(message: string)
    constructor(message: string, options: ExpiredTokenErrorOptions)
    constructor(message?: string, options?: ExpiredTokenErrorOptions) {
        super(message, options);
    }
}