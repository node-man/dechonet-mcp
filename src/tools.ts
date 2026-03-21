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
    description: 'Query DNS records (A, AAAA, MX, TXT, NS, SOA, CAA) for a domain. Checks DNSSEC, validates SPF/DMARC syntax, identifies misconfigurations with severity-rated diagnostics.',
    schema: {
      domain: z.string().describe('Domain name to query (e.g., example.com)'),
    },
    handler: async ({ domain }) => {
      try { return formatResult(await callApi(`/api/util/dns?query=${enc(domain)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'ssl_check',
    description: 'Verify SSL/TLS certificate — expiry, issuer, SAN, chain integrity, TLS version. Grades A+ to F based on certificate validity (40%), TLS version (25%), chain trust (15%), HSTS (20%).',
    schema: {
      host: z.string().describe('Hostname to check (e.g., example.com)'),
      port: z.number().default(443).describe('Port number (default: 443)'),
    },
    handler: async ({ host, port }) => {
      try { return formatResult(await callApi(`/api/util/ssl?host=${enc(host)}&port=${port}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'http_security',
    description: 'Trace HTTP redirects and audit security headers (CSP, HSTS, X-Frame-Options, COOP, CORP, COEP, Permissions-Policy). Grades A+ to F. Detects information leaks.',
    schema: {
      url: z.string().describe('URL to check (e.g., https://example.com)'),
    },
    handler: async ({ url }) => {
      try { return formatResult(await callApi(`/api/util/http?url=${enc(url)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'email_auth',
    description: 'Check email authentication: MX records, SPF, DMARC, DKIM (15 selectors), BIMI, MTA-STS, TLS-RPT, DANE. Blacklist check across all MX hosts. Returns 0-100 deliverability score.',
    schema: {
      domain: z.string().describe('Domain or IP to check (e.g., example.com or 1.2.3.4)'),
    },
    handler: async ({ domain }) => {
      try { return formatResult(await callApi(`/api/util/email?query=${enc(domain)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'port_scan',
    description: 'Scan common TCP ports to identify open services. Covers HTTP, HTTPS, SSH, FTP, SMTP, DNS, databases. Shows port number, service name, and response time.',
    schema: {
      host: z.string().describe('Hostname or IP to scan (e.g., example.com or example.com:443)'),
    },
    handler: async ({ host }) => {
      try { return formatResult(await callApi(`/api/util/port?host=${enc(host)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'dns_propagation',
    description: 'Check DNS propagation across 8+ global resolvers (Google, Cloudflare, Quad9, OpenDNS). Identifies which resolvers have stale cached values.',
    schema: {
      domain: z.string().describe('Domain to check'),
      type: z.enum(['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS']).default('A').describe('Record type'),
    },
    handler: async ({ domain, type }) => {
      try { return formatResult(await callApi(`/api/util/propagation?domain=${enc(domain)}&type=${type}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'reverse_dns',
    description: 'Reverse DNS (PTR) lookup for any IPv4/IPv6. Verifies forward-confirmed rDNS (FCrDNS). Identifies hosting provider from PTR patterns.',
    schema: {
      ip: z.string().describe('IP address to look up (IPv4 or IPv6)'),
    },
    handler: async ({ ip }) => {
      try { return formatResult(await callApi(`/api/util/reverse-dns?query=${enc(ip)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'asn_lookup',
    description: 'Look up ASN/BGP info for an IP or ASN number. Identifies network operator, prefixes, abuse contact. Classifies as cloud/CDN/ISP/hosting/enterprise.',
    schema: {
      query: z.string().describe('ASN (e.g., AS13335) or IP address'),
    },
    handler: async ({ query }) => {
      try { return formatResult(await callApi(`/api/util/asn?query=${enc(query)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'whois_lookup',
    description: 'RDAP/WHOIS lookup for domain registration data: registrar, dates, nameservers, status flags. Detects clientHold, pendingDelete.',
    schema: {
      domain: z.string().describe('Domain name to look up'),
    },
    handler: async ({ domain }) => {
      try { return formatResult(await callApi(`/api/util/rdap?query=${enc(domain)}`)); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'ip_info',
    description: 'Get public IP information: IPv4/IPv6, ISP, ASN, geolocation, proxy/VPN detection.',
    schema: {},
    handler: async () => {
      try { return formatResult(await callApi('/api/util/ip')); }
      catch (e: any) { return errorResult(e.message); }
    },
  },
  {
    name: 'email_header_analysis',
    description: 'Analyze email headers to trace delivery route, extract SPF/DKIM/DMARC results, detect delays and unencrypted hops.',
    schema: {
      headers: z.string().describe('Raw email headers to analyze (paste the full header text)'),
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
    description: 'Calculate subnet details from CIDR notation: network/broadcast address, host range, usable hosts, wildcard mask.',
    schema: {
      cidr: z.string().describe('IP with CIDR prefix (e.g., 192.168.1.0/24)'),
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
    description: 'Comprehensive security scan — runs DNS, SSL, HTTP, Email, Port, Propagation, Reverse DNS, ASN, and RDAP checks in parallel. Returns a 0-100 Health Score with A-F grade and prioritized actions.',
    schema: {
      domain: z.string().describe('Domain to scan comprehensively (e.g., example.com)'),
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
