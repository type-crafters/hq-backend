import assert from "assert";

class EnvironmentVariable {
    #name;
    #value;

    constructor(name, value) {
        this.#name = name;
        this.#value = value;
    }

    asString() {
        assert(this.#value, "Environment variable '" + this.#name + "' is not set.");
        return `${this.#value}`;
    }

    asInt() {
        assert(this.#value, "Environment variable '" + this.#name + "' is not set.");
        const int = parseInt(this.#value);
        assert(int, "Parsed string resolved to NaN.");
        return int;
    }

    asFloat() {
        assert(this.#value, "Environment variable '" + this.#name + "' is not set.");
        const float = parseFloat(this.#value);
        assert(float, "Parsed string resolved to NaN.");
        return float;
    }

    asBoolean() {
        assert(this.#value, "Environment variable '" + this.#name + "' is not set.");
        if (["true", "false"].includes(this.#value)) {
            return value === "true";
        }
        throw new TypeError("Attempted casting environment variable value to boolean but failed.")
    }
}

export class RequiresEnvironment {
    required = [];
    environment = new Map();

    constructor() {
        if (new.target === RequiresEnvironment) {
            throw new Error("Abstract base class 'RequiresEnvironment' cannot be instantiated directly.");
        }
    }

    checkEnvironment() {
        this.required.forEach(variable => {
            assert(this.environment.get(variable), "Missing required variable '" + variable + "' in internal definition.");
        });
    }

    /** @param {NodeJS.ProcessEnv} environment */
    setEnvironment(environment) {
        Object.entries(environment).forEach(([name, value]) => {
            this.environment[name] = value;
        });
        this.checkEnvironment();
    }

    getEnv(name) {
        const value = this.environment.get(name);
        return new EnvironmentVariable(name, value);
    }
}



