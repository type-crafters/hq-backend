export class Project {
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

    constructor({
        status,
        name,
        imageUrl,
        overview,
        details,
        href
    }) {
        this.status = status;
        this.name = name;
        this.imageUrl = imageUrl;
        this.overview = overview;
        this.details = details;
        this.href = href;
    }
}