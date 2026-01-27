export declare type Consumer<T> = (value: T) => void;
export declare type Mapper<T, U> = (value: T) => U;
export declare type Nullable<T> =  T | null;
export declare type Predicate<T> = (value: T) => boolean;
export declare type Supplier<T> = () => T;