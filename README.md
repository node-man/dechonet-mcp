# DechoNet MCP Server

Domain security reconnaissance tools for AI agents via [Model Context Protocol](https://modelcontextprotocol.io).

13 security tools — DNS, SSL, HTTP headers, email auth, port scan, propagation, reverse DNS, ASN/BGP, RDAP/WHOIS, subnet calc, and comprehensive security scan — callable from Claude Desktop and any MCP-compatible AI agent.

## Quick Start (Claude Desktop)

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dechonet": {
      "command": "npx",
      "args": ["-y", "dechonet-mcp"]
    }
  }
}
```

Or if installed locally:

```json
{
  "mcpServers": {
    "dechonet": {
      "command": "node",
      "args": ["/path/to/dechonet/mcp/build/index.js"]
    }
  }
}
```

Config file location:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Restart Claude Desktop. You'll see the DechoNet tools icon in the input area.

## Install

```bash
# Via npx (no install needed)
npx dechonet-mcp

# Or install globally
npm install -g dechonet-mcp
```

## Available Tools

| Tool | Description |
|------|-------------|
| `security_scan` | **Comprehensive scan** — 9 checks in parallel, 0-100 Health Score, A-F grade |
| `dns_lookup` | DNS records + DNSSEC + SPF/DMARC validation |
| `ssl_check` | SSL/TLS certificate, chain, TLS version, A-F grade |
| `http_security` | HTTP redirect trace + 10 security headers audit, A-F grade |
| `email_auth` | SPF, DMARC, DKIM, BIMI, MTA-STS, DANE + blacklist check |
| `port_scan` | Open TCP ports with service identification |
| `dns_propagation` | DNS propagation across 8+ global resolvers |
| `reverse_dns` | PTR record + FCrDNS verification |
| `asn_lookup` | ASN/BGP network identification + abuse contact |
| `whois_lookup` | RDAP/WHOIS domain registration data |
| `ip_info` | Public IP, ISP, ASN, proxy detection |
| `email_header_analysis` | Email delivery route tracing + auth results |
| `subnet_calc` | CIDR subnet calculator (offline) |

## Example Prompts

Once connected, try asking Claude:

- "Check the security posture of example.com"
- "Is the SSL certificate for mysite.com about to expire?"
- "What DNS records does example.com have?"
- "Scan the open ports on my-server.com"
- "Analyze these email headers: [paste headers]"
- "What's the ASN for 8.8.8.8?"
- "Calculate the subnet for 10.0.0.0/16"

## SSE Transport (Remote)

For remote/HTTP-based MCP connections:

```bash
cd mcp
npm run start:sse
# Server runs on http://localhost:3100
# SSE endpoint: http://localhost:3100/sse
```

## Development

```bash
cd mcp
npm install
npm run build    # TypeScript → build/
npm run dev      # Run with tsx (stdio)
npm run start:sse # Run SSE server
```

## How It Works

The MCP server calls DechoNet's public API (`https://dechonet.com/api/util/*`) and returns structured results with:
- **Status** (ok/warn/bad)
- **KPIs** (key performance indicators per tool)
- **Issues** with severity (critical/warning/info) and confidence levels
- **Actionable remediation steps**
- **Raw data** (full JSON)

All data comes from public sources (DNS, HTTP headers, SSL certificates, RDAP). No active exploitation.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DECHONET_URL` | `https://dechonet.com` | API base URL |
| `DECHONET_LOCALE` | `en` | Response language (`en` or `ko`) |
| `PORT` | `3100` | SSE server port |
