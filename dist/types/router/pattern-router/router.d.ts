import type { Result, Router } from '../../router';
export declare class PatternRouter<T> implements Router<T> {
    name: string;
    add(method: string, path: string, handler: T): void;
    match(method: string, path: string): Result<T>;
}
