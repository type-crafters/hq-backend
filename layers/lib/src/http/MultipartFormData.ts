import Busboy from "busboy";
import Stream from "stream";
import { StringParser } from "../util/StringParser.js";
import assert from "assert";

type FileHandlerFormat = Buffer | Stream.Readable;

interface MultipartFile<T extends FileHandlerFormat> {
    filename: string;
    encoding: string;
    contentType: string;
    data: T;
}

abstract class FileHandler<T extends FileHandlerFormat> {
    public abstract load(file: Stream.Readable): Promise<T>;
}

class BufferHandler extends FileHandler<Buffer> {
    public async load(file: Stream.Readable): Promise<Buffer> {
        const chunks: Buffer[] = [];
        for await (const chunk of file) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        return Buffer.concat(chunks);
    }
}

class StreamHandler extends FileHandler<Stream.Readable> {
    public async load(file: Stream.Readable): Promise<Stream.Readable> {
        return file;
    }
}

class FormDataParser<T extends FileHandlerFormat> {
    private handler: FileHandler<T>;
    private headers: Map<string, string>;
    public fields: Map<string, StringParser> = new Map();
    public files: Map<string, Array<MultipartFile<T>>> = new Map();
    private promises: Array<Promise<void>> = [];

    constructor(handler: FileHandler<T>, headers: Record<string, string>) {
        this.handler = handler;
        this.headers = new Map(Object.entries(headers));
    }

    public async process(stream: Stream.Readable): Promise<void> {
        const busboy = Busboy({ headers: Object.fromEntries(this.headers) });

        busboy.on("field", (name, value) => {
            this.fields.set(name, StringParser.of(value));
        });

        busboy.on("file", (name, file, info) => {
            const promise = this.handler.load(file)
                .then(data => {
                    const entry = {
                        filename: info.filename,
                        encoding: info.encoding,
                        contentType: info.mimeType,
                        data
                    } satisfies MultipartFile<T>;

                    if (!this.files.has(name)) {
                        this.files.set(name, []);
                    }

                    this.files.get(name)!.push(entry);
                });
            
            this.promises.push(promise);
        });

        return new Promise((resolve, reject) => {
            busboy.on("error", reject);
            busboy.on("finish", async () => {
                try {
                    await Promise.all(this.promises);
                    resolve();
                } catch (error) {
                    reject(error);
                }
            });

            stream.pipe(busboy);
        });
    }
}

export class MultipartFormData<T extends FileHandlerFormat> {
    private handler: FileHandler<T>;

    private constructor(handler: FileHandler<T>) {
        this.handler = handler;
    }

    public static buffered(): MultipartFormData<Buffer> {
        return new MultipartFormData(new BufferHandler());
    }

    public static streamed(): MultipartFormData<Stream.Readable> {
        return new MultipartFormData(new StreamHandler());
    }

    public usingHeaders(headers: Record<string, string>): FormDataParser<T> {
        const h: Record<string, string> = {};

        Object.entries(headers).forEach(([key, value]) => {
            h[key.toLowerCase()] = value;
        });

        assert(h["content-type"], "Missing required 'Content-Type' header.");

        return new FormDataParser(this.handler, h);
    }
}