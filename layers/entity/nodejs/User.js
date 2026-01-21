export class User {
    static UserMapper = class {
        /** @type {User} */
        #user;

        /** @param {User} user */
        constructor(user) {
            this.#user = user;
        }

        toClaims() {
            return {
                sub: this.#user.id,
                email: this.#user.email,
                roles: this.#user.roles
            };
        }
    }

    /** @returns {User.UserMapper} */
    mapper() {
        return new User.UserMapper(this);
    }

    /** @type {import("crypto").UUID} */
    id;
    /** @type {Date} */
    createdAt;
    /** @type {string} */
    email;
    /** @type {string} */
    name;
    /** @type {string[]} */
    roles;
    /** @type {string} */
    password;
    /** @type {string} */
    profilePictureUrl;
    /** @type {Date} */
    updatedAt;

    /**
     * @param {{
     *  id: import("crypto").UUID,
     *  createdAt: string,
     *  email: string,
     *  name: string,
     *  roles: string[],
     *  password: string,
     *  profilePictureUrl: string,
     *  updatedAt: string,
     *  args: any
     * }} params
    */
    constructor({
        id,
        createdAt,
        email,
        name,
        roles,
        password,
        profilePictureUrl,
        updatedAt,
        ...args
    }) {
        this.id = id;
        this.createdAt = new Date(createdAt);
        this.email = email;
        this.name = name;
        this.roles = roles;
        this.password = password;
        this.updatedAt = new Date(updatedAt);
        void args;
    }
}