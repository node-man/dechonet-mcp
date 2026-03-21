#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { createServer } from 'http';
import { tools } from './tools.js';
const PORT = parseInt(process.env.PORT || '3100', 10);
const server = new McpServer({
    name: 'dechonet',
    version: '1.0.0',
});
// Register all tools
for (const tool of tools) {
    server.tool(tool.name, tool.description, tool.schema, tool.handler);
}
// Track active transports for message routing
const transports = new Map();
const httpServer = createServer(async (req, res) => {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }
    const url = new URL(req.url || '/', `http://localhost:${PORT}`);
    if (url.pathname === '/sse' && req.method === 'GET') {
        const transport = new SSEServerTransport('/messages', res);
        transports.set(transport.sessionId, transport);
        res.on('close', () => {
            transports.delete(transport.sessionId);
        });
        await server.connect(transport);
        return;
    }
    if (url.pathname === '/messages' && req.method === 'POST') {
        const sessionId = url.searchParams.get('sessionId');
        if (!sessionId || !transports.has(sessionId)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid or missing sessionId' }));
            return;
        }
        const body = await readBody(req);
        const transport = transports.get(sessionId);
        await transport.handlePostMessage(req, res, body);
        return;
    }
    // Health check
    if (url.pathname === '/' || url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            name: 'dechonet-mcp',
            version: '1.0.0',
            tools: tools.map(t => t.name),
            transport: 'sse',
        }));
        return;
    }
    res.writeHead(404);
    res.end('Not found');
});
function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', (chunk) => { data += chunk; });
        req.on('end', () => {
            try {
                resolve(JSON.parse(data));
            }
            catch {
                resolve(data);
            }
        });
        req.on('error', reject);
    });
}
httpServer.listen(PORT, () => {
    console.error(`DechoNet MCP Server (SSE) running on http://localhost:${PORT}`);
    console.error(`  SSE endpoint: http://localhost:${PORT}/sse`);
    console.error(`  ${tools.length} tools available`);
});
