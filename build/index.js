#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { tools } from './tools.js';
const server = new McpServer({
    name: 'dechonet',
    version: '1.1.0',
});
// Register all tools. registerTool (not the legacy server.tool) so each
// tool ships title, annotations, and an outputSchema — handlers return
// structuredContent matching it alongside the text content.
for (const tool of tools) {
    server.registerTool(tool.name, {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.schema,
        outputSchema: tool.outputSchema,
        annotations: tool.annotations,
    }, tool.handler);
}
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error(`DechoNet MCP Server running (${tools.length} tools) via stdio`);
}
main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
});
