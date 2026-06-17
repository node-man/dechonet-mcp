import { z } from 'zod';

const BASE_URL = process.env.DECHONET_URL || 'https://dechonet.com';
const LOCALE = process.env.DECHONET_LOCALE || 'en';

interface ApiResponse {
  ok: boolean;
  data: any;
  error?: { code: string; message: string };
}

async function callApi(path: string): Promise<any> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'User-Agent': 'DechoNet-MCP/1.0', 'Accept-Language': LOCALE },
  });
  const json: ApiResponse = await res.json();
  if (!json.ok) {
    throw new Error(json.error?.message || `API error: ${res.status}`);
  }
  return json.data;
}

function formatResult(data: any): { content: Array<{ type: 'text'; text: string }> } {
  const interp = data.interpretation;
  const lines: string[] = [];

  if (interp) {
    lines.push(`Status: ${interp.status.toUpperCase()}`);
    if (interp.title) lines.push(interp.title);
    lines.push('');

    if (interp.kpis?.length) {
      lines.push('KPIs:');
      for (const k of interp.kpis) {
        lines.push(`  ${k.label}: ${k.value}`);
      }
      lines.push('');
    }

    if (interp.insight) {
      lines.push(`Summary: ${interp.insight.summary}`);
      if (interp.insight.detail) lines.push(`Detail: ${interp.insight.detail}`);
      lines.push('');
    }

    if (interp.issues?.length) {
      lines.push('Issues:');
      for (const iss of interp.issues) {
        lines.push(`  [${iss.severity}] ${iss.key}${iss.confidence ? ` (confidence: ${iss.confidence})` : ''}`);
      }
      lines.push('');
    }

    if (interp.actionItems?.length) {
      lines.push('Actions:');
      for (const a of interp.actionItems) {
        lines.push(`  - ${a}`);
      }
      lines.push('');
    }

    if (interp.securityGrade) {
      lines.push(`Security Grade: ${interp.securityGrade} (${interp.securityScore}/100)`);
    }
    if (interp.sslGrade) {
      lines.push(`SSL Grade: ${interp.sslGrade} (${interp.sslScore}/100)`);
    }
  }

  lines.push('---');
  lines.push('Raw data (JSON):');
  const rawJson = JSON.stringify(data.raw, null, 2);
  if (rawJson.length > 8000) {
    lines.push(rawJson.slice(0, 8000));
    lines.push(`\n... (truncated — ${rawJson.length} chars total. Use individual tool for full data.)`);
  } else {
    lines.push(rawJson);
  }

  return { content: [{ type: 'text' as const, text: lines.join('\n') }] };
}

function errorResult(msg: string) {
  return { content: [{ type: 'text' as const, text: `Error: ${msg}` }], isError: true as const };
}

export interface ToolDef {
  name: string;
  description: string;
  schema: Record<string, z.ZodTypeAny>;
  handler: (args: any) => Promise<any>;
}

export const tools: ToolDef[] = [
  {
    name: 'dns_lookup',
    description:
      'Query DNS records (A, AAAA, MX, TXT, NS, SOA, CAA) for a domain and validate email-related records, including DNSSEC presence and SPF/DMARC syntax, returning severity-rated diagnostics. ' +
      'Use this for a single authoritative answer about one domain. Use dns_propagation instead when you need to compare answers across multiple global resolvers (e.g., right after a change), or email_auth for a full SPF/DKIM/DMARC deliverability assessment. ' +
      'Read-only; requires no API key or authentication; subject to rate limiting. Returns a text report: status, KPI summary, detected issues, and recommended actions.',
    schema: {
      domain: z.string().describe("Registrable domain or hostname to query, without scheme or path (e.g., 'example.com' or 'mail.example.com'). Do not include 'http://' or a trailing slash."),
    },
    handler: async ({ domain }) => {
      try { return formatResult(await callApi(`/api/util/dns?query=${enc(domain)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'ssl_check',
    description:
      "Inspect a host's served TLS/SSL certificate and connection: expiry date, issuer, SAN list, chain integrity, TLS version, and HSTS, returning an A+ to F grade weighted by certificate validity (40%), TLS version (25%), chain trust (15%), and HSTS (20%). " +
      'Use this to diagnose certificate or HTTPS-handshake problems for one host. Use http_security instead to audit response security headers, or security_scan for an all-in-one domain report. ' +
      'Read-only: it completes a TLS handshake but sends no application data; requires no API key; rate-limited. Returns a text report: grade, expiry/issuer KPIs, issues, and actions.',
    schema: {
      host: z.string().describe("Hostname to inspect, without scheme (e.g., 'example.com'). The host portion of a pasted URL is also accepted."),
      port: z.number().default(443).describe('TCP port for the TLS handshake. Defaults to 443 (standard HTTPS); set this only for a non-standard HTTPS port such as 8443.'),
    },
    handler: async ({ host, port }) => {
      try { return formatResult(await callApi(`/api/util/ssl?host=${enc(host)}&port=${port}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'http_security',
    description:
      "Follow a URL's HTTP redirect chain and audit response security headers (CSP, HSTS, X-Frame-Options, COOP, CORP, COEP, Permissions-Policy), grading A+ to F and flagging information leaks such as server-version disclosure. " +
      'Use this for HTTP-layer/header posture. Use ssl_check instead for certificate or TLS-handshake issues, or security_scan for a full domain report. ' +
      'Read-only (an HTTP GET-style probe that sends no payload); requires no API key; rate-limited. Returns a text report: grade, header findings, redirect trace, issues, and actions.',
    schema: {
      url: z.string().describe("Full URL including scheme (e.g., 'https://example.com/path'). If the scheme is omitted, https:// is assumed. Redirects are followed starting from this URL."),
    },
    handler: async ({ url }) => {
      try { return formatResult(await callApi(`/api/util/http?url=${enc(url)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'email_auth',
    description:
      "Assess a domain's email authentication and deliverability posture: MX records, SPF, DMARC, DKIM (probes 15 common selectors), BIMI, MTA-STS, TLS-RPT, and DANE, plus a blacklist check across all MX hosts, returning a 0-100 deliverability score. " +
      'Use this for a full sending/receiving readiness review of a domain. Use dns_lookup instead if you only need raw TXT/MX records, or email_header_analysis to diagnose a specific message that was already sent. ' +
      'Read-only; requires no API key; rate-limited. Returns a text report: score, per-mechanism KPIs, issues, and actions.',
    schema: {
      domain: z.string().describe("Email domain to assess — the part after '@' (e.g., 'example.com'). An IP address is also accepted for reverse/PTR-based checks."),
    },
    handler: async ({ domain }) => {
      try { return formatResult(await callApi(`/api/util/email?query=${enc(domain)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'port_scan',
    description:
      'Probe a host for a fixed set of common TCP ports (HTTP, HTTPS, SSH, FTP, SMTP, DNS, and common databases) and report which are open, the service name, and the response time. ' +
      'BEHAVIOR: this makes an ACTIVE TCP connection to the target. It is non-intrusive — a connect probe only; it does not authenticate, send exploits, or transfer data — and changes nothing on the target (read-only), but the connection is visible in the target\'s logs, so only scan hosts you own or are explicitly authorized to test. ' +
      'Use this to confirm which services are exposed. Use ssl_check or http_security instead to assess a specific service\'s configuration. Requires no API key; rate-limited. Returns a per-port open/closed list with service names.',
    schema: {
      host: z.string().describe("Hostname or IP to probe (e.g., 'example.com' or '203.0.113.10'). A 'host:port' form is accepted to hint a specific port. Only supply targets you own or are authorized to test."),
    },
    handler: async ({ host }) => {
      try { return formatResult(await callApi(`/api/util/port?host=${enc(host)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'dns_propagation',
    description:
      'Query one DNS record across 8+ global public resolvers (Google, Cloudflare, Quad9, OpenDNS, and more) simultaneously and report which resolvers return stale versus updated values. ' +
      'Use this after changing a record to confirm worldwide propagation. Use dns_lookup instead for a single authoritative answer with SPF/DMARC validation. ' +
      'Read-only; requires no API key; rate-limited. Returns per-resolver values and a consistency verdict.',
    schema: {
      domain: z.string().describe("Domain whose record to compare across resolvers (e.g., 'example.com'), without scheme or path."),
      type: z.enum(['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS']).default('A').describe('DNS record type to compare across resolvers. Defaults to A (IPv4 address), the most common propagation check.'),
    },
    handler: async ({ domain, type }) => {
      try { return formatResult(await callApi(`/api/util/propagation?domain=${enc(domain)}&type=${type}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'reverse_dns',
    description:
      "Resolve the PTR (reverse DNS) record for an IPv4 or IPv6 address and verify forward-confirmed reverse DNS (FCrDNS) by checking that the PTR hostname resolves back to the same IP. Infers the hosting provider from PTR naming patterns. " +
      'Use this to validate mail-server rDNS or identify a single IP\'s host. Use asn_lookup instead for network/BGP ownership of the IP. ' +
      'Read-only; requires no API key; rate-limited. Returns the PTR hostname, FCrDNS pass/fail, and a provider guess.',
    schema: {
      ip: z.string().describe("IP address to reverse-resolve, IPv4 or IPv6 (e.g., '8.8.8.8' or '2001:4860:4860::8888'). Must be an IP, not a hostname."),
    },
    handler: async ({ ip }) => {
      try { return formatResult(await callApi(`/api/util/reverse-dns?query=${enc(ip)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'asn_lookup',
    description:
      'Look up Autonomous System (ASN) / BGP information for an IP address or AS number: the network operator, announced prefixes, abuse contact, and a classification (cloud, CDN, ISP, hosting, or enterprise). ' +
      'Use this to identify who runs a network or whether an IP is cloud/CDN-hosted. Use reverse_dns instead for the host-level PTR name of a single IP. ' +
      'Read-only; requires no API key; rate-limited. Returns operator, prefixes, classification, and abuse contact.',
    schema: {
      query: z.string().describe("An IP address (e.g., '1.1.1.1') or an AS number in 'AS####' form (e.g., 'AS13335')."),
    },
    handler: async ({ query }) => {
      try { return formatResult(await callApi(`/api/util/asn?query=${enc(query)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'whois_lookup',
    description:
      'Retrieve domain registration data via RDAP (with WHOIS fallback): registrar, creation/expiry/update dates, nameservers, and EPP status flags, highlighting risk states such as clientHold and pendingDelete. ' +
      'Use this for ownership, lifecycle, and expiry questions about a registered domain. Use dns_lookup instead for live DNS records, or reverse_dns/asn_lookup for IP-level ownership. ' +
      'Read-only; requires no API key; rate-limited. Returns registrar, key dates, nameservers, and status flags.',
    schema: {
      domain: z.string().describe("Registered domain name to look up (e.g., 'example.com'). A subdomain is normalized to its registrable domain."),
    },
    handler: async ({ domain }) => {
      try { return formatResult(await callApi(`/api/util/rdap?query=${enc(domain)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'ip_info',
    description:
      "Report information about the caller's own public IP as seen by the server: IPv4/IPv6 address, ISP, ASN, approximate geolocation, and proxy/VPN heuristics. " +
      "Takes no input — it reflects the egress IP of THIS MCP server's network, which is usually NOT the end user's IP. Use this to discover the server's outbound IP or test connectivity. To inspect a specific, known IP instead, use asn_lookup or reverse_dns. " +
      'Read-only; requires no API key; rate-limited.',
    schema: {},
    handler: async () => {
      try { return formatResult(await callApi('/api/util/ip')); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'email_header_analysis',
    description:
      'Parse raw email headers to reconstruct the delivery path (each Received hop in order), extract SPF/DKIM/DMARC authentication results, measure per-hop delays, and flag unencrypted (non-TLS) hops. ' +
      'Use this to diagnose a specific message that was already delivered — spoofing, delays, or where mail was lost. Use email_auth instead to assess a domain\'s sending configuration before sending. ' +
      'Read-only; requires no API key; rate-limited. INPUT is the full raw header block. OUTPUT is a text report containing: the ordered hop route, per-mechanism auth results (pass/fail), detected inter-hop delays, and the encryption status of each hop.',
    schema: {
      headers: z.string().describe("The complete raw email header block, copied verbatim — every line from the first 'Received:'/'From:' down to the blank line before the body. Paste as-is, including folded continuation lines; do not include the message body."),
    },
    handler: async ({ headers }) => {
      try {
        const res = await fetch(`${BASE_URL}/api/util/email-header`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'User-Agent': 'DechoNet-MCP/1.0', 'Accept-Language': LOCALE },
          body: JSON.stringify({ headers }),
        });
        const json: ApiResponse = await res.json();
        if (!json.ok) throw new Error(json.error?.message || 'API error');
        return formatResult(json.data);
      } catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'subnet_calc',
    description:
      'Compute IPv4 subnet details from CIDR notation entirely locally — no network call: network and broadcast addresses, usable host range, total usable hosts, subnet mask, and wildcard mask. /31 and /32 are handled per RFC 3021 (point-to-point / single host). ' +
      'Use this for IPv4 address planning. It does not query DNS or contact any host, so it is purely computational. ' +
      'Requires no API key and is NOT rate-limited (computed in-process). Returns the calculated fields as text.',
    schema: {
      cidr: z.string().describe("IPv4 address with a CIDR prefix length 0-32 (e.g., '192.168.1.0/24'). IPv4 only; host bits may be any address inside the block."),
    },
    handler: async ({ cidr }) => {
      // Subnet calculation is client-side only, compute here
      try {
        const [ip, prefixStr] = cidr.split('/');
        const prefix = parseInt(prefixStr, 10);
        if (!ip || isNaN(prefix) || prefix < 0 || prefix > 32) throw new Error('Invalid CIDR notation');

        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some((p: number) => isNaN(p) || p < 0 || p > 255)) throw new Error('Invalid IP');

        const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
        const network = (ipNum & mask) >>> 0;
        const broadcast = (network | ~mask) >>> 0;
        const firstHost = prefix >= 31 ? network : (network + 1) >>> 0;
        const lastHost = prefix >= 31 ? broadcast : (broadcast - 1) >>> 0;
        const totalHosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : Math.pow(2, 32 - prefix) - 2;

        const toIp = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
        const toMask = (m: number) => toIp(m);
        const wildcard = (~mask) >>> 0;

        const result = {
          network: toIp(network),
          broadcast: toIp(broadcast),
          firstHost: toIp(firstHost),
          lastHost: toIp(lastHost),
          subnetMask: toMask(mask),
          wildcardMask: toMask(wildcard),
          totalHosts,
          prefix,
        };

        return { content: [{ type: 'text' as const, text: Object.entries(result).map(([k, v]) => `${k}: ${v}`).join('\n') }] };
      } catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'security_scan',
    description:
      'One-shot comprehensive audit of a domain: runs DNS, SSL, HTTP headers, email auth, port scan, DNS propagation, reverse DNS, and ASN/RDAP checks in parallel, then computes a 0-100 Health Score with an A-F grade and a prioritized action list. ' +
      "Use this as the default starting point for \"is this domain healthy/secure?\" questions. Call the individual tools (e.g., ssl_check, email_auth) instead when you need depth on one area. " +
      'BEHAVIOR: this includes an ACTIVE port_scan of the domain\'s host, so only run it on domains you own or are authorized to test. Read-only otherwise; requires no API key; rate-limited (it makes multiple backend calls). Returns the score, per-area breakdown, top actions, and per-area summaries.',
    schema: {
      domain: z.string().describe("Domain to audit end-to-end (e.g., 'example.com'). Scheme and path are stripped. NOTE: the host is also port-scanned, so use only targets you are authorized to test."),
    },
    handler: async ({ domain }) => {
      try {
        const d = enc(domain);
        const httpTarget = domain.startsWith('http') ? domain : `https://${domain}`;
        const [dns, ssl, http, email, port, propagation, rdap] = await Promise.allSettled([
          callApi(`/api/util/dns?query=${d}`),
          callApi(`/api/util/ssl?host=${d}`),
          callApi(`/api/util/http?url=${enc(httpTarget)}`),
          callApi(`/api/util/email?query=${d}`),
          callApi(`/api/util/port?host=${d}`),
          callApi(`/api/util/propagation?domain=${d}&type=A`),
          callApi(`/api/util/rdap?query=${d}`),
        ]);

        const get = (r: PromiseSettledResult<any>) => r.status === 'fulfilled' ? r.value : null;
        const results: Record<string, any> = {
          dns: get(dns), ssl: get(ssl), http: get(http), email: get(email),
          port: get(port), propagation: get(propagation), rdap: get(rdap),
        };

        // Extract origin IP for rDNS + ASN
        const aRecord = results.dns?.raw?.records?.find((r: any) => r.type === 'A');
        if (aRecord) {
          const [rdns, asn] = await Promise.allSettled([
            callApi(`/api/util/reverse-dns?query=${enc(aRecord.value)}`),
            callApi(`/api/util/asn?query=${enc(aRecord.value)}`),
          ]);
          results.reverseDns = get(rdns);
          results.asn = get(asn);
        }

        // Calculate health score
        const weights: Record<string, number> = { rdap: 10, dns: 18, ssl: 18, http: 14, email: 14, propagation: 8, port: 8, reverseDns: 5, asn: 5 };
        let score = 100;
        const areas: string[] = [];

        for (const [key, weight] of Object.entries(weights)) {
          const r = results[key];
          if (!r) { score -= weight; areas.push(`${key}: FAILED (-${weight})`); continue; }
          const interp = r.interpretation;
          if (!interp) continue;
          const criticals = interp.issues?.filter((i: any) => i.severity === 'critical')?.length || 0;
          const warnings = interp.issues?.filter((i: any) => i.severity === 'warning')?.length || 0;
          const lost = Math.min(weight, Math.round(weight * 0.4 * criticals + weight * 0.15 * warnings));
          score -= lost;
          const status = lost === 0 ? 'OK' : `ISSUE (-${lost})`;
          areas.push(`${key}: ${status}`);
        }
        score = Math.max(0, score);
        const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';

        const lines = [
          `=== ${domain} Security Report ===`,
          `Health Score: ${score}/100 (Grade ${grade})`,
          '',
          'Area Breakdown:',
          ...areas.map(a => `  ${a}`),
          '',
        ];

        // Collect all actions
        const allActions: string[] = [];
        for (const r of Object.values(results)) {
          if (r?.interpretation?.actionItems) allActions.push(...r.interpretation.actionItems);
        }
        if (allActions.length > 0) {
          lines.push('Priority Actions:');
          allActions.slice(0, 5).forEach((a, i) => lines.push(`  ${i + 1}. ${a}`));
          lines.push('');
        }

        lines.push('Individual Results (JSON):');
        for (const [key, r] of Object.entries(results)) {
          if (r) {
            lines.push(`\n--- ${key.toUpperCase()} ---`);
            lines.push(`Status: ${r.interpretation?.status || 'unknown'}`);
            if (r.interpretation?.insight?.summary) lines.push(`Summary: ${r.interpretation.insight.summary}`);
          }
        }

        return { content: [{ type: 'text' as const, text: lines.join('\n') }] };
      } catch (e: any) { return errorResult(e.message); }
    },
  },
];

function enc(s: string): string {
  return encodeURIComponent(s);
}
