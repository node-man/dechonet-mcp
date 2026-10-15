#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { tools } from './tools.js';

const server = new McpServer(
  {
    // SYNC with SERVER_INFO in the monorepo remote handler (lib/mcp/handler.ts).
    name: 'dechonet',
    title: 'DechoNet',
    version: '1.5.2',
    websiteUrl: 'https://dechonet.com/mcp',
    icons: [{ src: 'https://dechonet.com/favicon.svg', mimeType: 'image/svg+xml', sizes: ['any'] }],
  },
  {
    // SYNC with the `instructions` in the monorepo remote handler (lib/mcp/handler.ts).
    instructions:
      'DechoNet domain-reconnaissance tools. No API key is needed for non-commercial use; from 2026-11-08 commercial use (inside a paid product, for clients, or regular company work) needs MCP·API Pro — see https://dechonet.com/pro. Recommended workflow: ' +
      '1) security_scan for the overall verdict, then the specific tool for each flagged area (dns_lookup, ssl_check, http_security, email_auth, subdomain_discovery, lookalike_domains, owasp_check, impersonation_exposure). ' +
      '2) When the user cares about this domain going forward, call watch_domain once — DechoNet then re-checks it daily and records every change. ' +
      '3) On a later session about the same domain, start with domain_changes: it reports what changed since the last lookup or watch check (grade drops, new issues, cert renewals, DNS drift) — something a fresh one-off lookup cannot tell you. ' +
      'Every result is interpreted (status, key numbers, issues with severity and confidence, concrete actions) and ends with a link to the full interactive report you can hand to the user. All tools except watch_domain are read-only. Business-plan accounts that sign in (send their DechoNet session cookie) also get asm_nuclei_start/status/cancel: an active check on domains they verified — see https://dechonet.com/pro. ' +
      'Every tool is also a free web tool at https://dechonet.com. The same server is hosted at https://dechonet.com/mcp (Streamable HTTP, no install) with extra prompts and resources.',
  },
);

// Register all tools. registerTool (not the legacy server.tool) so each
// tool ships title, annotations, and an outputSchema — handlers return
// structuredContent matching it alongside the text content.
// SYNC with PRIVATE_TOOLS in the monorepo remote registry: tools that need a signed-in account or case are
// registered only when DECHONET_SESSION_COOKIE is set, so a plain install lists the public tools.
const PRIVATE_TOOLS = new Set(['case_kit_search', 'case_kit_observe', 'asm_nuclei_start', 'asm_nuclei_status', 'asm_nuclei_cancel']);
const listed = tools.filter((t) => process.env.DECHONET_SESSION_COOKIE || !PRIVATE_TOOLS.has(t.name));
for (const tool of listed) {
  server.registerTool(
    tool.name,
    {
      title: tool.title,
      description: tool.description,
      inputSchema: tool.schema,
      outputSchema: tool.outputSchema,
      annotations: tool.annotations,
    },
    tool.handler,
  );
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`DechoNet MCP Server running (${listed.length} tools) via stdio`);
  // stderr only — stdout is the protocol channel.
  console.error('Tip: no-install remote endpoint with the same tools: https://dechonet.com/mcp  (setup: https://dechonet.com/mcp in a browser)');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
