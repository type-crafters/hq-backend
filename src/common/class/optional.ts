export class Optional<T> {
    private readonly value: T | null | undefined;

    private constructor(value: T | null | undefined) {
        this.value = value;
    }

    private static noSuchElement(): Error {
        return new Error("Attempted to read null or undefined value.");
    }

    public static of<T>(value: T): Optional<T> {
        if (value == null) {
            throw Optional.noSuchElement();
        }
        return new Optional(value);
    }

    public static ofNullable<T>(value: T | null | undefined): Optional<T> {
        return new Optional(value);
    }

    public static empty<T>(): Optional<T> {
        return new Optional<T>(null);
    }

    public isPresent(): boolean {
        return this.value != null;
    }

    public ifPresent(consumer: (value: T) => void): void {
        if (this.isPresent()) {
            consumer(this.value as T);
        }
    }

    public get(): T {
        if (!this.isPresent()) {
            throw Optional.noSuchElement();
        }
        return this.value as T;
    }

    public orElse(other: T): T {
        return this.isPresent() ? (this.value as T) : other;
    }

    public orElseGet(provider: () => T): T {
        return this.isPresent() ? (this.value as T) : provider();
    }

    public orElseThrow(errorSupplier: () => Error): T {
        if (this.isPresent()) {
            return this.value as T;
        }
        throw errorSupplier();
    }

    public map<U>(mapper: (value: T) => U): Optional<U> {
        return this.isPresent()
            ? Optional.ofNullable(mapper(this.value as T))
            : Optional.empty<U>();
    }

    public flatMap<U>(mapper: (value: T) => Optional<U>): Optional<U> {
        return this.isPresent()
            ? mapper(this.value as T)
            : Optional.empty<U>();
    }

    public filter(predicate: (value: T) => boolean): Optional<T> {
        if (!this.isPresent()) {
            return this;
        }

        return predicate(this.value as T)
            ? this
            : Optional.empty<T>();
    }
}