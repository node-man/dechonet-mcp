import { z } from 'zod';
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
