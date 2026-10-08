# DechoNet MCP Server

Domain security reconnaissance for AI agents via the [Model Context Protocol](https://modelcontextprotocol.io).

**25 tools. No API key needed for non-commercial use.** Phishing/smishing link checks, exposed admin page checks (admin screens, test servers, dev tools left open), DNS, SSL/TLS, post-quantum TLS readiness, HTTP security headers, email authentication, port scan, DNS propagation, reverse DNS, ASN/BGP, RDAP/WHOIS, subdomain discovery (CT logs), lookalike/typosquat detection, OWASP-mapped observable checks, brand-impersonation exposure, go-live readiness, **domain change history** — what changed since the last check — **infrastructure history and pivots** (past nameservers/IPs/issuers, and other domains seen on the same rare infrastructure), and a daily **watch** you can set from the agent.

Every result comes back interpreted, not just as raw JSON: a status, the key numbers, each issue with severity and confidence, and the concrete action to take. That is what an agent needs to tell a human what to do next.

**Part of [DechoNet](https://dechonet.com).** Every tool here is also a free web tool at **[dechonet.com](https://dechonet.com)** — no sign-up — backed by error-fix [guides](https://dechonet.com/guides). This package brings the same checks to AI agents.

## Zero-install: remote endpoint

No npx, no install. Point any MCP client that speaks Streamable HTTP at:

```
https://dechonet.com/mcp
```

Claude Desktop / Claude Code (`claude mcp add --transport http dechonet https://dechonet.com/mcp`), Cursor, and other HTTP-capable clients connect directly. The remote endpoint also serves 3 curated prompts (`audit_domain`, `monitor_setup`, `investigate_changes`) and 2 reference resources.

## Quick Start (stdio, Claude Desktop)

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
| `phishing_link_check` | **Is this link a scam?** — paste a text message or URL; follows shorteners, checks domain age, Korean brand impersonation, APK downloads, phishing feeds |
| `exposure_map` | **Admin pages open to the internet?** — subdomains from CT, each opened once: admin screens, staging, dev tools, VPN logins, default pages, directory listings (counts; per-host detail for the verified owner on the web report) |
| `security_scan` | **Comprehensive scan** — 9 checks in parallel, 0-100 Health Score, A-F grade |
| `dns_lookup` | DNS records + DNSSEC + SPF/DMARC validation |
| `ssl_check` | SSL/TLS certificate, chain, expiry, HSTS, CT history, A-F grade |
| `http_security` | HTTP redirect trace + 10 security headers audit, A-F grade |
| `email_auth` | SPF, DMARC, DKIM, BIMI, MTA-STS, DANE + blacklist check |
| `port_scan` | Open TCP ports with service identification |
| `dns_propagation` | DNS propagation across 8+ global resolvers |
| `reverse_dns` | PTR record + FCrDNS verification |
| `asn_lookup` | ASN/BGP network identification + abuse contact |
| `whois_lookup` | RDAP/WHOIS domain registration data |
| `subdomain_discovery` | Passive subdomain enumeration from CT logs, operational-name flags (dev/staging/admin), wildcard detection |
| `lookalike_domains` | Typosquat variants that are actually registered — homoglyph, affix (brand-login), TLD swap, keyboard slips — with the domain's own defensive registrations separated out |
| `owasp_check` | OWASP-mapped checks that can be observed passively (headers, TLS, exposed files), honest about what is out of scope |
| `impersonation_exposure` | Brand impersonation exposure grade: third-party lookalikes + exposed operational subdomains + wildcard certs |
| `golive_check` | Go-live readiness — DNS, propagation, SSL, HTTP, registration in one READY / CAUTION / NOT READY verdict |
| `domain_history` | Past nameservers, A/AAAA, MX, certificate issuer, registrar (and an IP's ASN/PTR) with first and last seen — from DechoNet's own observations, not passive DNS |
| `infrastructure_pivot` | Other domains DechoNet saw with the same nameserver, IP, MX, issuer or registrar. **Needs a free API key** (`DECHONET_API_KEY`); shared infrastructure returns a count only |
| `domain_changes` | What changed since the last check — status, grade, issuer, DNS, issues. Works from lookup history even without a watch |
| `pqc_readiness` | Post-quantum TLS readiness: hybrid X25519MLKEM768 key exchange, whether the origin server or a CDN edge provides it, certificate signature algorithms. External indicator, not a full PQC audit |
| `watch_domain` | Register a domain for daily re-checks (SSL, DNS, HTTP, RDAP) so `domain_changes` accumulates a timeline. The only tool that writes; idempotent |
| `ip_info` | Public IP, ISP, ASN, proxy detection |
| `email_header_analysis` | Email delivery route tracing + auth results |
| `subnet_calc` | CIDR subnet calculator (offline) |

Every tool response ends with a link to the full interactive report on dechonet.com for the human behind the agent.

## Example Prompts

Once connected, try asking Claude:

- "Audit the security posture of example.com"
- "Is the SSL certificate for mysite.com about to expire?"
- "Which subdomains of example.com are exposed in CT logs?"
- "Are there registered lookalike domains of mybrand.com?"
- "How exposed is mybrand.com to impersonation?"
- "Is example.com ready to go live?"
- "What changed on example.com since the last check?"
- "Analyze these email headers: [paste headers]"
- "What's the ASN for 8.8.8.8?"

## Local SSE Transport

For a self-hosted HTTP/SSE bridge (the hosted remote endpoint above is usually simpler):

```bash
npm run start:sse
# Server runs on http://localhost:3100
# SSE endpoint: http://localhost:3100/sse
```

## Development

```bash
npm install
npm run build    # TypeScript → build/
npm run dev      # Run with tsx (stdio)
npm run start:sse # Run SSE server
```

## How It Works

The MCP server calls DechoNet's public API (`https://dechonet.com/api/util/*`) — the same backend as the [dechonet.com](https://dechonet.com) web tools — and returns structured results with:
- **Status** (ok/warn/bad)
- **KPIs** (key numbers per tool)
- **Issues** with severity (critical/warning/info) and confidence levels
- **Actionable remediation steps**
- **Raw data** (full JSON)

All data comes from public sources (DNS, HTTP headers, SSL certificates, CT logs, RDAP). Passive by design: no active exploitation, and a registered lookalike is reported as a fact to verify, never as an accusation.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DECHONET_URL` | `https://dechonet.com` | API base URL |
| `DECHONET_LOCALE` | `en` | Response language (`en` or `ko`) |
| `DECHONET_API_KEY` | — | Optional free API key from your [DechoNet account](https://dechonet.com/monitoring): your own rate-limit bucket, and required for `infrastructure_pivot` |
| `PORT` | `3100` | SSE server port |

## Terms of use

Free use (with or without a key) is for **non-commercial purposes** from **November 8, 2026** — personal learning and research, checking your own domains, non-profit work. Using DechoNet inside a paid product, for clients, or regularly for company work needs **MCP·API Pro** ([dechonet.com/pro](https://dechonet.com/pro)); until payments open, ask at support@dechonet.com. Full terms: [dechonet.com/terms](https://dechonet.com/terms) §4.

## About DechoNet

[DechoNet](https://dechonet.com) is a domain security reconnaissance platform — distributed observation, cross-verification. The same diagnostics ship three ways: free web tools, error-fix guides, and this MCP server.

- 🌐 **Web tools** (free, no sign-up): https://dechonet.com
- 📘 **Guides** (fix common DNS/SSL/HTTP/email errors): https://dechonet.com/guides
- 🔔 **Monitoring** (daily re-checks, change history): https://dechonet.com/pro
- 🐦 **X**: https://x.com/Dechonetwork

MIT licensed. Issues and PRs welcome.
