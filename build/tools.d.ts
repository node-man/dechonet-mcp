import { z } from 'zod';
export interface ToolDef {
    name: string;
    description: string;
    schema: Record<string, z.ZodTypeAny>;
    handler: (args: any) => Promise<any>;
}
export declare const tools: ToolDef[];
