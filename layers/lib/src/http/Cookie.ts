import assert from "assert";
import { StringParser } from "../util/StringParser.js";
import { Optional } from "../types/index.js";

interface CookieArgs {
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

class CookieGetter {
    private name: string;

    constructor(name: string) {
        this.name = name;
    }

    public from(cookie: string): StringParser {
        assert(this.name, "Called CookieGetter::from without providing a cookie name.");

        const cookies = cookie.split(";").map(c => c.trim()).filter(c => !!c);
        const thisCookie = cookies.find(c => c.slice(0, c.indexOf("=")).trim() === this.name);

        assert(thisCookie, "Cookie with name '" + this.name + "' not found.");
        return StringParser.of(decodeURIComponent(thisCookie.slice(thisCookie.indexOf("="))));
    }
}

class CookieBuilder {
    private _name?: string;
    private _value?: string;
    private _httpOnly?: boolean;
    private _secure?: boolean;
    private _domain?: string;
    private _path?: string;
    private _sameSite: Optional<"Strict" | "Lax" | "None">;
    private _expires: Optional<Date>;
    private _maxAge: Optional<number>;

    public name(name: string): this {
        this._name = name;
        return this;
    }

    public value(value: string): this {
        this._value = value;
        return this;
    }

    public httpOnly(httpOnly: boolean): this {
        this._httpOnly = httpOnly;
        return this;
    }

    public secure(secure: boolean): this {
        this._secure = secure;
        return this;
    }

    public domain(domain: string): this {
        this._domain = domain;
        return this;
    }

    public path(path: string): this {
        this._path = path;
        return this;
    }

    public sameSite(sameSite: "Strict" | "Lax" | "None"): this {
        this._sameSite = sameSite;
        return this;
    }

    public expires(expires: Date): this {
        this._expires = expires;
        return this;
    }

    public maxAge(maxAge: number): this {
        this._maxAge = maxAge;
        return this;
    }

    build(): Cookie {
        assert(this._name, "Cookies must, at least, define a name and a value.");
        assert(this._value, "Cookies must, at least, define a name and a value.");
        return new Cookie({
            name: this._name,
            value: this._value,
            httpOnly: this._httpOnly,
            secure: this._secure,
            domain: this._domain,
            path: this._path,
            sameSite: this._sameSite,
            expires: this._expires,
            maxAge: this._maxAge
        });
    }
}

export class Cookie {
    public name: string;
    public value: string;
    public httpOnly?: boolean;
    public secure?: boolean;
    public domain?: string;
    public path?: string;
    public sameSite: Optional<"Strict" | "Lax" | "None">;
    public expires: Optional<Date>;
    public maxAge: Optional<number>;

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
    }: CookieArgs) {
        assert(name, "Cookies must, at least, define a name and a value.");
        assert(value, "Cookies must, at least, define a name and a value.")
        assert((!sameSite || ["Strict", "Lax", "None"].includes(sameSite)), 
            "A cookie's SameSite attribute must be either 'Strict', 'Lax', or 'None'."
        );
        assert(sameSite !== "None" || secure, 
            "Cookies with a SameSite attribute set to 'None' must be secure."
        );

        this.name = name;
        this.value = value;
        this.httpOnly = httpOnly;
        this.secure = secure;
        this.domain = domain;
        this.path = path;
        this.sameSite = sameSite;
        this.expires = expires;
        this.maxAge = maxAge;
    }

    static builder() {
        return new CookieBuilder();
    }

    static get(name: string) {
        return new CookieGetter(name);
    }

    toString() {
        const cookie = [`${this.name}=${this.value}`];

        if (this.expires) {
            cookie.push(`Expires=${this.expires.toUTCString()}`);
        }

        if (this.maxAge !== undefined) {
            cookie.push(`Max-Age=${this.maxAge}`);
        }

        if (this.domain) {
            cookie.push(`Domain=${this.domain}`);
        }

        if (this.path) {
            cookie.push(`Path=${this.path}`);
        }

        if (this.sameSite) {
            cookie.push(`SameSite=${this.sameSite}`);
        }

        if (this.secure) {
            cookie.push("Secure");
        }

        if (this.httpOnly) {
            cookie.push("HttpOnly");
        }

        return cookie.join("; ");
    }
}