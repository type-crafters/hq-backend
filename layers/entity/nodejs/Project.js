export class Project {
    /** @type {import("crypto").UUID} */
    id;
    /** @type {string} */
    status;
    /** @type {string} */
    name;
    /** @type {string} */
    imageUrl;
    /** @type {string} */
    overview;
    /** @type {string} */
    details;
    /** @type {string[]} */
    tags;
    /** @type {string} */
    href;

    /**
     * @param {{
     *  id: string;
     *  status: string,
     *  name: string,
     *  imageUrl: string,
     *  overview: string,
     *  details: string,
     *  tags: string[],
     *  href: string,
     *  args: any
     * }} params 
     */
    constructor({
        id,
        status,
        name,
        imageUrl,
        overview,
        details,
        tags,
        href,
        ...args
    }) {
        this.id = id;
        this.status = status;
        this.name = name;
        this.imageUrl = imageUrl;
        this.overview = overview;
        this.details = details;
        this.tags = tags;
        this.href = href;
        void args;
    }
}