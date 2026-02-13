import type { Nullable, Optional } from "../types/index.js";

interface StringParserArgs<T extends boolean> {
    value: Optional<Nullable<string>>;
    strict: T;
}

type StrictReturn<T extends boolean, U> = T extends true ? U : Nullable<U>;

export class StringParser<T extends boolean = false> {
    private _strict: T;
    private _value: Nullable<string>;

    private constructor({ value, strict }: StringParserArgs<T>) {
        this._value = value ?? null;
        this._strict = strict
    }

    private get trimmed() {
        if (this._value === null) {
            if (this._strict) throw TypeError("StringParser::strict expects a non-null 'value' string.");
            return "";
        }
        return (this._value!).trim();
    }

    public static of(value: Optional<Nullable<string>>): StringParser<false> {
        return new StringParser({ value, strict: false });
    }

    public strict(): StringParser<true> {
        return new StringParser({ value: this._value, strict: true });
    }

    public toString(): StrictReturn<T, string> {
        if (this._strict && this._value === null) {
            throw TypeError("StringParser::strict expects a non-null 'value' string.");
        }
        return this._value as StrictReturn<T, string>;
    }

    public valueOf(): StrictReturn<T, string> {
        return this.toString();
    }

    public toInt(): StrictReturn<T, number> {
        const int = parseInt(this.trimmed, 10);

        if (isNaN(int)) {
            if (this._strict) {
                throw TypeError("Could not convert arbitrary string '" + this._value + "' to number.");
            } else {
                return null as StrictReturn<T, number>;
            }
        }

        return int as StrictReturn<T, number>;
    }

    public toFloat(): StrictReturn<T, number> {
        const float = parseFloat(this.trimmed);

        if (isNaN(float)) {
            if (this._strict) {
                throw TypeError("Could not convert arbitrary string '" + this._value + "' to number.");
            } else {
                return null as StrictReturn<T, number>;
            }
        }

        return float as StrictReturn<T, number>;
    }

    public toNumber(): StrictReturn<T, number> {
        return this.toFloat();
    }

    public toBoolean(): StrictReturn<T, boolean> {
        const lower = this.trimmed.toLowerCase();

        if (lower !== "true" && lower !== "false") {
            if (this._strict) throw TypeError("Could not convert arbitrary string '" + this._value + "' to boolean.");
            return null as StrictReturn<T, boolean>;
        }

        return (lower === "true") as StrictReturn<T, boolean>;
    }

    public toBool(): StrictReturn<T, boolean> {
        return this.toBoolean();
    }
}