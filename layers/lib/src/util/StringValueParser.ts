import assert from "assert";

export class StringValueParser {
    private name: string;
    private value?: string;

    private get trimmed() {
        assert(this.value, "Variable '" + this.name + "' is undefined.")
        const trim = this.value.trim()
        assert(trim, "Variable '" + this.name + "' is empty.");
        return trim;
    }

    constructor(name: string, value?: string) {
        this.name = name;
        this.value = value;
    }

    toString(): string {
        return this.trimmed;
    }

    toInt(): number {
        const int: number = parseInt(this.trimmed, 10);
        assert(!Number.isNaN(int), "Attempted to parse variable '" + this.name + "' but returned NaN.");
        return int;
    }

    toFloat(): number {
        const float: number = parseFloat(this.trimmed);
        assert(!Number.isNaN(float), "Attempted to parse variable '" + this.name + "' but returned NaN.");
        return float;
    }

    toBoolean(): boolean {
        const lower: string = this.trimmed.toLowerCase();
        assert(["true", "false"].includes(lower), "Attempted to parse variable '" + this.name + "' but failed.")
        return lower === "true";
    }
}