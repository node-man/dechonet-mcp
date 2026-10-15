#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { tools } from './tools.js';

const server = new McpServer(
  {
    // SYNC with SERVER_INFO in the monorepo remote handler (lib/mcp/handler.ts).
    name: 'dechonet',
    title: 'DechoNet',
    version: '1.5.6',
    websiteUrl: 'https://dechonet.com/mcp',
    icons: [{ src: 'https://dechonet.com/favicon.svg', mimeType: 'image/svg+xml', sizes: ['any'] }],
  },
  {
    // SYNC with the `instructions` in the monorepo remote handler (lib/mcp/handler.ts).
    instructions:
      'DechoNet domain-reconnaissance tools: public, read-only checks of domains, URLs and IP addresses (DNS, TLS certificates, HTTP security headers, email authentication, registration data, phishing links, exposure) and the change history DechoNet has observed. No account is needed; an optional DechoNet API key (Authorization: Bearer dn_…) gives a separate rate-limit bucket. Terms of use: https://dechonet.com/terms. ' +
      'Typical flow: security_scan for an overall verdict, then the specific tool for each flagged area (dns_lookup, ssl_check, http_security, email_auth, subdomain_discovery, lookalike_domains, owasp_check, impersonation_exposure). ' +
      'domain_changes reports what changed since DechoNet last looked at a domain (grade drops, new issues, certificate renewals, DNS drift). ' +
      'watch_domain is the only tool that writes: it registers a domain for daily re-checks, so use it when the user asks to monitor a domain. ' +
      'Each result gives a status, key numbers, issues with severity and confidence, recommended fixes and a link to the full report on dechonet.com. Signed-in DechoNet business accounts (DECHONET_SESSION_COOKIE) also see asm_nuclei_start/status/cancel, an active check limited to domains they have verified. ' +
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
