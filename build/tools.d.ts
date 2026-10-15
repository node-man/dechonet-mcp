import { AsyncLocalStorage } from 'node:async_hooks';
import { z } from 'zod';
export interface ReceiptRef {
    tool: string;
    id: string;
    url: string;
}
export declare const receiptScope: AsyncLocalStorage<ReceiptRef[]>;
export declare const receiptsShape: z.ZodOptional<z.ZodArray<z.ZodObject<{
    tool: z.ZodString;
    id: z.ZodString;
    url: z.ZodString;
}, "strip", z.ZodTypeAny, {
    tool: string;
    id: string;
    url: string;
}, {
    tool: string;
    id: string;
    url: string;
}>, "many">>;
export declare function withReceipts(result: any, receipts: ReceiptRef[]): any;
export interface ToolAnnotations {
    title: string;
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint: boolean;
    openWorldHint: boolean;
}
export interface ToolDef {
    name: string;
    title: string;
    description: string;
    schema: Record<string, z.ZodTypeAny>;
    outputSchema: Record<string, z.ZodTypeAny>;
    annotations: ToolAnnotations;
    handler: (args: any) => Promise<any>;
}
export declare const tools: ToolDef[];
