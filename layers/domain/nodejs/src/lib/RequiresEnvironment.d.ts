import type { Consumer } from "../types";

declare class EnvironmentVariable {
    private name: string;
    private value: string;

    constructor(name: string, value?: string);

    public asString(): string;
    public asInt(): number;
    public asFloat(): number;
    public asBoolean(): boolean;
}


export declare abstract class RequiresEnvironment {
    protected required: string[];
    protected environment: Map<string, string>;

    constructor();

    protected checkEnvironment(): void;
    public setEnvironment: Consumer<NodeJS.ProcessEnv>;
    public getEnv(name: string): EnvironmentVariable;
}