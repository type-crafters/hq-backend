import { Cookie } from "./Cookie.js";
import { Header } from "./Header.js";
import { HttpCode } from "./HttpCode.js";
import { MediaType } from "./MediaType.js";

type JSONLike =
    | string
    | number
    | boolean
    | null
    | JSONLike[]
    | { [key: string]: JSONLike }

export interface ResponseObject {
    body?: string;
    cookies?: Array<string>;
    headers?: Record<string, string>;
    isBase64Encoded?: boolean;
    statusCode: number;
}

class HttpResponseBuilder {
    private _status?: number;
    private _isBase64Encoded?: boolean;
    private _headers: Map<string, string> = new Map();
    private _cookies: Map<string, Cookie> = new Map();
    private _body?: string;

    private get hasBody(): boolean {
        return this._body !== undefined;
    }

    /**
     * Sets the HTTP status code of the response to a known or custom HTTP code.
     * @param code The HTTP code to set the response status to. 
     * Arbitrary numbers may be used to set custom codes. 
     * @returns The updated builder object.
     */
    public status(code: number): this
    public status(code: HttpCode): this
    public status(code: number): this {
        this._status = code;
        return this;
    }

    /**
     * Sets the isBase64Encoded field of the response to the value given.
     * @param encoded Whether the response's body is base64 encoded
     * @returns The updated builder object.
     */
    public setBase64Encoded(encoded: boolean): this {
        this._isBase64Encoded = encoded;
        return this;
    }

    /**
     * Sets the isBase64Encoded field of the response to true. 
     * This achieves the same effect as using `HttpResponseBuilder.setBase64Encoded(true)`.
     * @returns The updated builder object.
     */
    public base64Encoded(): this {
        this._isBase64Encoded = true;
        return this;
    }

    /**
     * Sets a cookie on the HTTP response.
     * @param cookie An object representing the cookie to add.
     * @param replace If true while another cookie of the same name exists,
     * this method will replace the previous cookie. Otherwise, this cookie will be omitted. 
     * @returns The updated builder object.
     */
    public setCookie(cookie: Cookie, replace: boolean = true) {
        if (!this._cookies.has(cookie.name) || replace) {
            this._cookies.set(cookie.name, cookie);
        }
        return this;
    }

    /**
     * Sets multiple cookies in a single call.
     * @param cookies The cookies to set for the HTTP response.
     * @warning This method will overwrite any previously set cookie with the same name as any of the cookies provided.
     */
    public setCookies(...cookies: Cookie[]): this {
        cookies.forEach(c => this._cookies.set(c.name, c));
        return this;
    }

    /**
     * Sets a header on the HTTP response.
     * @param name The name of the header to add to the response. Common header names are provided under the `Header` enum.
     * @param value The value of the header being set. Common media types are provided under the `MediaType` enum.
     * @param replace If true while another cookie of the same name exists,
     * this method will replace the previous cookie. Otherwise, this cookie will be omitted. 
     * @returns The updated builder object.
     */
    public setHeader(name: string, value: string, replace: boolean): this
    public setHeader(name: Header, value: string, replace: boolean): this
    public setHeader(name: string, value: MediaType, replace: boolean): this
    public setHeader(name: Header, value: MediaType, replace: boolean): this
    public setHeader(name: string, value: string, replace: boolean = true): this {
        if (!this._headers.has(name) || replace) {
            this._headers.set(name, value);
        }
        return this;
    }

    /**
     * Sets the response body as a string.
     * @param body The body of the response.
     * @returns The updated builder object.
     */
    public setBody(body: string): this {
        this._body = body;
        return this;
    }

    /**
     * Sets the body of the response to the provided text.
     * This method is equivalent to calling `setHeader('Content-Type', 'text/plain')` 
     * and `setBody(text)` on the same HttpResponseBuilder object.
     * @param text the text to set as the body of the response
     * @returns The updated builder object
     */
    public text(text: string): this {
        this._headers.set(Header.ContentType, MediaType.TEXT_PLAIN);
        this._body = text;
        return this;
    }

    /**
     * Sets the body of the response to the provided text.
     * This method is equivalent to calling `setHeader('Content-Type', 'application/json')` 
     * and `setBody(JSON.stringify(json))` on the same HttpResponseBuilder object.
     * @param json the JSON-serializable object to set to the body of the response.
     * @returns The updated builder object
     */
    public json<T extends JSONLike = JSONLike>(json: T): this {
        this._headers.set(Header.ContentType, MediaType.APPLICATION_JSON);
        this._body = JSON.stringify(json);
        return this;
    }

    /**
     * Sets the body of the response to the provided text.
     * This method is equivalent to calling `setHeader('Content-Type', 'text/html')` 
     * and `setBody(html)` on the same HttpResponseBuilder object.
     * @param html the HTML to set to the response.
     * @returns The updated builder object
     * @warning This method does not sanitize HTML before setting it.
     */
    public html(html: string): this {
        this._headers.set(Header.ContentType, MediaType.TEXT_HTML);
        this._body = html;
        return this;
    }

    public build() {
        const response: ResponseObject = {
            statusCode: this._status ?? 200
        };

        if (this.hasBody && !this._headers.has(Header.ContentType)) {
            this._headers.set(Header.ContentType, MediaType.APPLICATION_OCTET_STREAM);
        }
        
        if (this._headers.size) {
            response.headers = Object.fromEntries(this._headers);
        }

        if (this._cookies.size) {
            response.cookies = Array.from(this._cookies.values(), c => c.toString());;
        }

        if (this._isBase64Encoded) {
            response.isBase64Encoded = true;
        }

        if (this.hasBody) {
            response.body = this._body;
        }

        return response;
    }

}

export class HttpResponse {
    public static builder(): HttpResponseBuilder {
        return new HttpResponseBuilder();
    }
}