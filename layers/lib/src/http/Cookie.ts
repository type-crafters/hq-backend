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
        return StringParser.of(decodeURIComponent(thisCookie.slice(thisCookie.indexOf("=") + 1)));
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
        if (name == null || value == null) {
            throw new TypeError("Cookies must, at least, define a name and a value.");
        }

        if (sameSite != null && !["Strict", "Lax", "None"].includes(sameSite)) {
            throw new TypeError("A cookie's SameSite attribute must be either 'Strict', 'Lax', or 'None'.");
        }

        if (sameSite === "None" && !secure) {
            throw new TypeError("Cookies with a SameSite attribute set to 'None' must be secure.");
        }

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

    public static from(cookiestr: string): Cookie {
        const args: Record<string, any> = {};
        const [kvp, ...attributes] = cookiestr.split(";").map(w => w.trim());
        const [namestr, ...valuestr] = kvp.split("=");
        const attrMap = new Map(attributes.map(attr => {
            const [name, ...valuelist] = attr.toLowerCase().split("=");
            const value = valuelist.join("=");
            return [name.trim(), value.trim()];
        }));

        if (attrMap.has("httponly")) {
            args.httpOnly = true;
        }

        if (attrMap.has("secure")) {
            args.secure = true;
        }

        if (attrMap.has("domain")) {
            args.domain = attrMap.get("domain");
        }

        if (attrMap.has("path")) {
            args.path = attrMap.get("path");
        }

        if (attrMap.has("samesite") && ["strict", "lax", "none"].includes(attrMap.get("samesite")!)) {
            const ss = attrMap.get("samesite")!;
            args.sameSite =  ss.charAt(0).toUpperCase() + ss.slice(1).toLowerCase();
        }

        if (attrMap.has("max-age")) {
            args.maxAge = StringParser.of(attrMap.get("max-age")).strict().toInt();
        }

        if (attrMap.has("expires")) {
            args.expires = new Date(attrMap.get("expires")!);
        }

        return new Cookie({ ...args, name: namestr.trim(), value: valuestr.join("=").trim() });
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