export class GlobalErrorHandler {
    /**
     * @param {unknown} error 
     * @returns {{ statusCode: number, body: string }}
     */
    static forError(error) {
        /** @type {Error} */
        const exception = error instanceof Error ? error : new Error("Non-error thrown");
        console.error([
            "=".repeat(64),
            "APPLICATION ERROR",
            "Type: " + exception.name,
            "Message: " + exception.message,
            "Cause: " + exception.cause,
            "Stack trace: " + exception.stack,
            "=".repeat(64)
        ].join("\n"));

        return {
            statusCode: 500,
            body: JSON.stringify({
                message: "Internal Server Error."
            })
        };
    }
}