export interface CliArgs {
    tool: string | null;
    value: string | null;
    json: boolean;
    raw: boolean;
    failOn: 'bad' | 'warn' | null;
    port: number | null;
    help: boolean;
}
/** Pure: argv (after the script) → what to do. */
export declare function parseArgs(argv: string[]): CliArgs;
/** Pure: whether the result reaches the --fail-on level — its status, or for the all-in-one scan its grade (bad = D/F, warn = C or below). */
export declare function failsOn(r: {
    status?: string;
    verdict?: string;
    grade?: string;
} | undefined, failOn: CliArgs['failOn']): boolean;
/** Pure: the human report — the tool's text without the raw JSON block (kept with --raw). */
export declare function humanText(text: string, raw: boolean): string;
export declare function runCli(argv: string[]): Promise<number>;
