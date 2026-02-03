import assert from "assert";
import { StringValueParser } from "./StringValueParser.js";

export abstract class RequiresEnvironment {
    protected required: Set<string> = new Set();
    protected environment: Map<string, string> = new Map();

    constructor(environment: NodeJS.ProcessEnv) {
        Object.entries(environment).forEach(([name, value]) => this.environment.set(name, value!));
        this.required.forEach(variable => assert(
            this.environment.has(variable), 
            "Missing required environment variable '" + variable + "' in internal definition."
        ));
    }

    public getEnv(name: string): StringValueParser {
        return new StringValueParser(name, this.environment.get(name));
    }
}