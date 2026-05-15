export class Duration {
    private readonly millis: number;

    public static get ZERO(): Duration {
        return new Duration(0);
    }

    private constructor(millis: number) {
        this.millis = millis;
    }

    static of(duration: Duration): Duration {
        return new Duration(duration.millis);
    }

    static ofMillis(millis: number): Duration {
        return new Duration(millis);
    }

    static ofSeconds(seconds: number): Duration {
        return new Duration(seconds * 1_000);
    }

    static ofMinutes(minutes: number): Duration {
        return new Duration(minutes * 60 * 1_000);
    }

    static ofHours(hours: number): Duration {
        return new Duration(hours * 60 * 60 * 1_000);
    }

    static ofDays(days: number): Duration {
        return new Duration(days * 24 * 60 * 60 * 1_000);
    }

    toMillis(): number {
        return this.millis;
    }

    valueOf(): number {
        return this.millis;
    }

    toSeconds(): number {
        return this.millis / 1_000;
    }

    toMinutes(): number {
        return this.millis / (60 * 1_000);
    }

    toHours(): number {
        return this.millis / (60 * 60 * 1_000);
    }

    toDays(): number {
        return this.millis / (24 * 60 * 60 * 1_000);
    }

    plus(duration: Duration): Duration {
        return new Duration(this.millis + duration.millis);
    }

    minus(duration: Duration): Duration {
        return new Duration(this.millis - duration.millis);
    }

    multipliedBy(factor: number): Duration {
        return new Duration(this.millis * factor);
    }

    fromNow(): Date {
        return new Date(Date.now() + this.millis);
    }

    ago(): Date {
        return new Date(Date.now() - this.millis);
    }

    toString(): string {
        return `${this.millis}ms`;
    }
}