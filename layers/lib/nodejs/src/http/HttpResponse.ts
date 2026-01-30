import { Cookie } from "./Cookie.js";
import { MediaType } from "./MediaType.js";
import { Header } from "./Header.js";
import { HttpCode } from "./HttpCode.js";

/** @experimental */
export interface ResponseObject {
    statusCode?: number;
    isBase64Encoded?: boolean;
    headers?: Record<string, string>;
    cookies?: string[];
    body?: string;
}

/** @experimental */
export class HttpResponse {
    private _status: number;
    private _isBase64Encoded: boolean;
    private _cookies: Map<string, Cookie>;
    private _headers: Map<string, string>;
    private body: string;

    constructor() {
        this._status = 200;
        this._isBase64Encoded = false;
        this._headers = new Map<string, string>();
        this._cookies = new Map<string, Cookie>();
        this.body = "";
    }

    public status(code: HttpCode | number): this {
        this._status = code;
        return this;
    }

    public base64encoded(encoded: boolean): this {
        this._isBase64Encoded = encoded;
        return this;
    }

    public setCookie(cookie: Cookie, replace: boolean = true): this {
        if (!this._cookies.has(cookie.name) || replace) {
            this._cookies.set(cookie.name, cookie);
        }
        return this;
    }

    public setHeader(
        name: Header | string,
        value: MediaType | string,
        replace: boolean = true
    ): this {
        if (!this._headers.has(name) || replace) {
            this._headers.set(name, value);
        }
        return this;
    }

    public json(json: unknown): this {
        this._headers.set(Header.ContentType, MediaType.APPLICATION_JSON);
        this.body = JSON.stringify(json);

        return this;
    }

    public text(text: string): this {
        this._headers.set(Header.ContentType, MediaType.TEXT_PLAIN);
        this.body = text;

        return this;
    }

    public html(html: string): this {
        this._headers.set(Header.ContentType, MediaType.TEXT_HTML);
        this.body = html;

        return this;
    }

    public parse(): ResponseObject {
        return Object.fromEntries(Object.entries({
            statusCode: this._status,
            isBase64Encoded: this._isBase64Encoded,
            headers: Object.fromEntries(this._headers),
            cookies: Array.from(this._cookies).map(cookie => cookie.toString()),
            body: this.body
        }).filter(([_, value]) =>
            value != null // null, undefined
            &&
            !(Array.isArray(value) && !value.length) // []
            &&
            !Number.isNaN(value) // NaN
            &&
            !(typeof value === "object" && !Object.keys(value).length) // {}
        ));
    }
}