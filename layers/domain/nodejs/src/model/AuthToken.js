export class AuthToken {
    static #TOKEN_ISSUER = "org.typecrafters";

    jti;
    exp;
    iat;
    iss;
    sub;
    typ;

    constructor({
        jti,
        exp,
        iat,
        sub
    } = {}) {
        if (new.target === AuthToken) {
            throw new Error("Abstract class 'AuthToken' cannot be instantiated directly.");
        }
        
        this.iss = AuthToken.#TOKEN_ISSUER;
        this.jti = jti;
        this.exp = exp;
        this.iat = iat;
        this.sub = sub;
    }
}