export interface ErrorResponse { 
    statusCode: number; 
    body: string
}

export class GlobalExceptionHandler {
    static forError(error: unknown): ErrorResponse;
}