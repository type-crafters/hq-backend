import assert from "assert";

class CookieGetter {
    #name;
    #value;

    constructor(name) {
        this.#name = name;
    }

    from(cookie) {
        assert(this.#name, "Called CookieGetter::from without providing a cookie name.")

        const cookies = cookie.split(";").map(c => c.trim()).filter(c => !!c);
        const thisCookie = cookies.find(c => c.split("=")[0].trim() === this.#name);

        assert(thisCookie, "Cookie with provided name '" + this.#name + "' was not found.");

        this.#value = decodeURIComponent(thisCookie.split("=").slice(1).join("="));
        return this;
    }

    asString() {
        assert(this.#value, "Missing value for cookie '" + this.#name + "'.");
        return `${this.#value}`;
    }

    asInt() {
        assert(this.#value, "Missing value for cookie '" + this.#name + "'.");
        const int = parseInt(this.#value);
        assert(int, "Parsed string resolved to NaN.");
        return int;
    }

    asFloat() {
        assert(this.#value, "Missing value for cookie '" + this.#name + "'.");
        const float = parseFloat(this.#value);
        assert(float, "Parsed string resolved to NaN.");
        return float;
    }

    asBoolean() {
        assert(this.#value, "Missing value for cookie '" + this.#name + "'.");
        if (["true", "false"].includes(this.#value)) {
            return value === "true";
        }
        throw new TypeError("Attempted casting cookie value to boolean but failed.")
    }
}

class CookieBuilder {
    #_name;
    #_value;
    #_httpOnly;
    #_secure;
    #_domain;
    #_path;
    #_sameSite;
    #_expires;
    #_maxAge;

    name(name) {
        this.#_name = name;
        return this;
    }

    value(value) {
        this.#_value = value;
        return this;
    }

    httpOnly(httpOnly) {
        this.#_httpOnly = httpOnly;
        return this;
    }

    secure(secure) {
        this.#_secure = secure;
        return this;
    }

    domain(domain) {
        this.#_domain = domain;
        return this;
    }

    path(path) {
        this.#_path = path;
        return this;
    }

    sameSite(sameSite) {
        this.#_sameSite = sameSite;
        return this;
    }

    expires(expires) {
        this.#_expires = expires;
        return this;
    }

    maxAge(maxAge) {
        this.#_maxAge = maxAge;
        return this;
    }

    build() {
        return new Cookie({
            name: this.#_name,
            value: this.#_value,
            httpOnly: this.#_httpOnly,
            secure: this.#_secure,
            domain: this.#_domain,
            path: this.#_path,
            sameSite: this.#_sameSite,
            expires: this.#_expires,
            maxAge: this.#_maxAge
        });
    }
}

export class Cookie {
    #_name;
    #_value;
    #_httpOnly;
    #_secure;
    #_domain;
    #_path;
    #_sameSite;
    #_expires;
    #_maxAge;

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
    } = {}) {
        if (name == null || value == null) {
            throw new TypeError("Cookies must, at least, define a name and a value.");
        }

        if (sameSite && !["Strict", "Lax", "None"].includes(sameSite)) {
            throw new TypeError("A cookie's SameSite attribute must be either 'Strict', 'Lax', or 'None'.");
        }

        if (sameSite === "None" && secure !== true) {
            throw new TypeError("Cookies with a SameSite attribute set to None must be secure.");
        }
        this.#_name = name;
        this.#_value = value;
        this.#_httpOnly = httpOnly;
        this.#_secure = secure;
        this.#_domain = domain;
        this.#_path = path;
        this.#_sameSite = sameSite;
        this.#_expires = expires;
        this.#_maxAge = maxAge;
    }

    static builder() {
        return new CookieBuilder();
    }

    static get(name) {
        return new CookieGetter(name);
    }

    toString() {
        let str = `${this.#_name}=${this.#_value};`;

        if (this.#_expires) {
            str += ` Expires=${this.#_expires.toUTCString()};`;
        }

        if (this.#_maxAge !== undefined) {
            str += ` Max-Age=${this.#_maxAge};`;
        }

        if (this.#_domain) {
            str += ` Domain=${this.#_domain};`;
        }

        if (this.#_path) {
            str += ` Path=${this.#_path};`;
        }

        if (this.#_sameSite) {
            str += ` SameSite=${this.#_sameSite};`;
        }

        if (this.#_secure === true) {
            str += ` Secure;`;
        }

        if (this.#_httpOnly === true) {
            str += ` HttpOnly;`;
        }

        return str;
    }
}
