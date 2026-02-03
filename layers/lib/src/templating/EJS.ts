import ejs from "ejs";

export class EJS<Asynchronous extends boolean = false> {
    private template: string;
    private asynchronous: boolean = false;

    private constructor(template: string) {
        this.template = template;
    }

    static render(template: string): EJS<false> {
        return new EJS(template);
    }

    public async(): EJS<true> {
        this.asynchronous = true;
        return new EJS(this.template);
    }

    public using(data: Record<string, any>): Asynchronous extends true ? Promise<string> : string {
        return ejs.render(this.template, data, { async: this.asynchronous }) as any;
    }
}