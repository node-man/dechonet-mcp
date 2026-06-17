#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { tools } from './tools.js';
const server = new McpServer({
    name: 'dechonet',
    version: '1.0.3',
});
// Register all 13 tools
for (const tool of tools) {
    server.tool(tool.name, tool.description, tool.schema, tool.handler);
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
