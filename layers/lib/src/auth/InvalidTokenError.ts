export interface InvalidTokenErrorOptions {
    cause?: unknown;
}

export class InvalidTokenError extends Error {
    constructor()
    constructor(message: string)
    constructor(message: string, options: InvalidTokenErrorOptions)
    constructor(message?: string, options?: InvalidTokenErrorOptions) {
        super(message, options);
    }
}
