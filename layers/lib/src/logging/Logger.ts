export class LoggerFactory {
    public static forFunction<T extends Function>(fn: T): Logger<T> {
        return new Logger(fn);
    }
}

class Logger<T extends Function> {
    private static readonly TRACE = "TRACE";
    private static readonly LOG = "LOG";
    private static readonly DEBUG = "DEBUG";
    private static readonly INFO = "INFO";
    private static readonly WARNING = "WARNING";
    private static readonly ERROR = "ERROR";

    private static readonly DATE_FORMATTER = new Intl.DateTimeFormat("en-US", {
        timeZone: "EST",
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true
    });

    private name: string;


    constructor(fn: T) {
        this.name = fn.name || "<anonymous>";
    }

    private get spacing() {
        return " ".repeat(
            Math.max(
                ...[Logger.TRACE, Logger.DEBUG, Logger.INFO, Logger.WARNING, Logger.ERROR]
                    .map(s => s.length)
            ) + 1
        );
    }

    private get formattedDate() {
        const now = new Date();
        return Logger.DATE_FORMATTER.format(now) + "." + now.getMilliseconds().toString().padStart(3, "0");
    }

    private formatValue(value: unknown) {
        if (value instanceof Error) {
            return [`Unhandled ${value.constructor.name}:`, value.message, value.stack].join("\n")
        }

        if (typeof value === "string") {
            return value;
        }

        try {
            return JSON.stringify(value);
        } catch {
            return String(value);
        }
    }

    private log(message: string, level: string): void {
        const words: string[] = [];

        words.push(this.formattedDate);
        words.push("-");
        words.push(`[${level}]`);
        words.push(this.spacing);
        words.push(`(${this.name})`);
        words.push(message);

        console.log(words.join(" "));
    }

    public error(value: unknown): void {
        this.log(this.formatValue(value), Logger.ERROR);
    }

    public warn(value: unknown): void {
        this.log(this.formatValue(value), Logger.WARNING);
    }

    public info(value: unknown): void {
        this.log(this.formatValue(value), Logger.INFO);
    }

    public debug(value: unknown): void {
        this.log(this.formatValue(value), Logger.DEBUG);
    }

    public trace(value: unknown): void {
        this.log(this.formatValue(value), Logger.TRACE);
    }
}