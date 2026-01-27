declare class CookieBuilder {
    private _name: string;
    private _value: string;
    private _httpOnly: boolean;
    private _secure: boolean;
    private _domain: string;
    private _path: string;
    private _sameSite: "Strict" | "Lax" | "None";
    private _expires: Date;
    private _maxAge: number;

    public name(name: string): this;
    public value(value: string): this;
    public httpOnly(httpOnly: boolean): this;
    public secure(secure: boolean): this;
    public domain(domain: string): this;
    public path(path: string): this;
    public sameSite(sameSite: "Strict" | "Lax" | "None"): this;
    public expires(expires: Date): this;
    public maxAge(maxAge: number): this;

    public build(): Cookie;
}

export declare interface CookieOptions {
    name: string;
    value: string;
    httpOnly?: boolean;
    secure?: boolean;
    domain?: string;
    path?: string;
    sameSite?: "Strict" | "Lax" | "None";
    expires?: Date;
    maxAge?: number;
}

export class Cookie {
    constructor({
        name,
        value,
        httpOnly,
        secure,
        domain,
        path,
        sameSite,
        expires,
        maxAge
    }: CookieOptions);

    static builder(): CookieBuilder;

    toString(): string;
}
