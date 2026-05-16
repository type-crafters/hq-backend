export class Space {
    private static KB: number = 1_000;
    private static MB: number = 1_000_000;
    private static GB: number = 1_000_000_000;
    private static TB: number = 1_000_000_000_000;

    private static KiB: number = 1024;
    private static MiB: number = 1_048_576;
    private static GiB: number = 1_073_741_824;
    private static TiB: number = 1_099_511_627_776;

    private constructor(private readonly bytes: number) {}

    public static ofBytes(bytes: number): Space {
        return new Space(bytes);
    }

    public static ofKilobytes(kilobytes: number): Space {
        return new Space(kilobytes * this.KB);
    }

    public static ofKibibytes(kibibytes: number): Space {
        return new Space(kibibytes * this.KiB);
    }

    public static ofMegabytes(megabytes: number): Space {
        return new Space(megabytes * this.MB);
    }

    public static ofMebibytes(mebibytes: number): Space {
        return new Space(mebibytes * this.MiB);
    }

    public static ofGigabytes(gigabytes: number): Space {
        return new Space(gigabytes * this.GB);
    }

    public static ofGibibytes(gibibytes: number): Space {
        return new Space(gibibytes * this.GiB);
    }

    public static ofTerabytes(terabytes: number): Space {
        return new Space(terabytes * this.TB);
    }

    public static ofTebibytes(tebibytes: number): Space {
        return new Space(tebibytes * this.TiB);
    }

    public toBytes(): number {
        return this.bytes;
    }

    public valueOf(): number {
        return this.toBytes();
    }

    public toKilobytes(): number {
        return this.bytes / Space.KB;
    }

    public toKibibytes(): number {
        return this.bytes / Space.KiB;
    }

    public toMegabytes(): number {
        return this.bytes / Space.MB;
    }

    public toMebibytes(): number {
        return this.bytes / Space.MiB;
    }

    public toGigabytes(): number {
        return this.bytes / Space.GB;
    }

    public toGibibytes(): number {
        return this.bytes / Space.GiB;
    }

    public toTerabytes(): number {
        return this.bytes / Space.TB;
    }

    public toTebibytes(): number {
        return this.bytes / Space.TiB;
    }
}