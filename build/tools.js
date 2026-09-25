import { z } from 'zod';
const BASE_URL = process.env.DECHONET_URL || 'https://dechonet.com';
const LOCALE = process.env.DECHONET_LOCALE || 'en';
async function callApi(path) {
    const res = await fetch(`${BASE_URL}${path}`, {
        headers: { 'User-Agent': 'DechoNet-MCP/1.0', 'Accept-Language': LOCALE },
    });
    const json = await res.json();
    if (!json.ok) {
        throw new Error(json.error?.message || `API error: ${res.status}`);
    }
    return json.data;
}
async function postApi(path, payload) {
    const res = await fetch(`${BASE_URL}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'DechoNet-MCP/1.0', 'Accept-Language': LOCALE },
        body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!json.ok)
        throw new Error(json.error?.message || `API error: ${res.status}`);
    return json.data;
}
// Human-facing report URL appended to every tool response. The MCP→person
// bridge: agents relay this link to their user, and the tool page auto-runs
// the same lookup from the 24h cache, so the click lands on the same result
// instantly. src=mcp-report attributes those visits separately from both
// 'mcp' (agent calls) and organic web. Always points at the public site,
// even when DECHONET_URL targets a dev backend — the report is for humans.
function reportUrl(page, param, value) {
    const base = `https://dechonet.com/util/${page}`;
    return param && value !== undefined && value !== null
        ? `${base}?${param}=${encodeURIComponent(String(value))}&src=mcp-report`
        : `${base}?src=mcp-report`;
}
const annotate = (title, openWorld = true) => ({
    title,
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: openWorld,
});
// Structured output shared by every interpretation-backed tool (declared as
// outputSchema; handlers return a matching structuredContent alongside the
// text). Raw JSON stays text-only so structured results remain small.
// SYNC with INTERP_OUTPUT_SCHEMA in the monorepo remote registry.
const interpOutputShape = {
    status: z.string().describe("Overall verdict, e.g. 'good' | 'warning' | 'bad' | 'info' | 'unknown'"),
    summary: z.string().optional().describe('One-paragraph interpretation of the result'),
    kpis: z.array(z.object({ label: z.string(), value: z.string() })).optional().describe('Key metrics as label/value pairs'),
    issues: z.array(z.object({ severity: z.string(), key: z.string() })).optional().describe('Detected problems, severity-rated'),
    actions: z.array(z.string()).optional().describe('Recommended next actions, most important first'),
    grade: z.string().optional().describe('Letter grade (A+ to F) when the tool grades the target'),
    score: z.number().optional().describe('0-100 score when the tool scores the target'),
    reportUrl: z.string().describe('Human-facing interactive report for this exact lookup on dechonet.com'),
};
const subnetOutputShape = {
    network: z.string().describe('Network address'),
    broadcast: z.string().describe('Broadcast address'),
    firstHost: z.string().describe('First usable host'),
    lastHost: z.string().describe('Last usable host'),
    subnetMask: z.string().describe('Dotted-decimal subnet mask'),
    wildcardMask: z.string().describe('Wildcard (inverse) mask'),
    totalHosts: z.number().describe('Usable host count'),
    prefix: z.number().describe('CIDR prefix length'),
    reportUrl: z.string().describe('Human-facing interactive report on dechonet.com'),
};
const scanOutputShape = {
    score: z.number().describe('Health Score 0-100'),
    grade: z.string().describe('Letter grade A+ to F'),
    areas: z.array(z.object({ area: z.string(), verdict: z.string() })).describe('Per-area verdicts'),
    actions: z.array(z.string()).optional().describe('Top recommended actions'),
    reportUrl: z.string().describe('Human-facing interactive report on dechonet.com'),
};
// SYNC with OWASP_OUTPUT_SCHEMA in the monorepo remote registry.
const owaspOutputShape = {
    grade: z.string().describe('OWASP posture grade A+ to F, over the observable categories only'),
    score: z.number().describe('0-100 across the categories that could be evaluated'),
    checks: z.array(z.object({ code: z.string(), status: z.string(), findingCount: z.number().optional() }))
        .describe('Per observable category: Secure Headers, A02, A05, A06'),
    notObservable: z.array(z.string()).optional().describe('Top 10 categories NOT checked (need authenticated/active testing)'),
    reportUrl: z.string().describe('Human-facing interactive report on dechonet.com'),
};
// SYNC with IMPERSONATION_OUTPUT_SCHEMA in the monorepo remote registry.
const impOutputShape = {
    grade: z.string().describe('Exposure grade A+ (low exposure) to F (high exposure)'),
    score: z.number().describe('0-100, higher = less exposed'),
    typosquatCount: z.number().describe('Live third-party lookalike/typosquat domains (variants on the domain\'s own nameservers/IP are excluded)'),
    riskySubdomainCount: z.number().describe('Exposed operational subdomains found'),
    wildcard: z.boolean().optional().describe('Whether a wildcard certificate exists'),
    reportUrl: z.string().describe('Human-facing interactive report on dechonet.com'),
};
// SYNC with DOMAIN_CHANGES_OUTPUT_SCHEMA in the monorepo remote registry.
const domainChangesOutputShape = {
    domain: z.string(),
    watched: z.boolean().describe('Whether the domain is under an active daily watch'),
    changeCount: z.number().optional().describe('Number of changes recorded'),
    changes: z.array(z.object({ endpoint: z.string().optional(), kind: z.string(), summary: z.string(), changedAt: z.string().optional() })).optional().describe('Recorded changes, newest first'),
    historyChangeCount: z.number().optional().describe('Changes found between the last two stored lookups per tool (no watch needed)'),
    historyChanges: z.array(z.object({ endpoint: z.string().optional(), kind: z.string(), summary: z.string(), since: z.string().optional(), changedAt: z.string().optional() })).optional().describe('Lookup-to-lookup changes, newest first'),
    reportUrl: z.string().describe('Where a human can start or manage monitoring'),
};
// SYNC with WATCH_DOMAIN_OUTPUT_SCHEMA in the monorepo remote registry.
const watchDomainOutputShape = {
    domain: z.string(),
    watches: z.array(z.object({ tool: z.string(), endpoint: z.string().optional(), url: z.string().describe('Public change-history page for this watch') })).describe('One entry per tool now under a daily watch'),
    failed: z.array(z.string()).optional().describe('Tools that could not be watched (rate limit or error)'),
    reportUrl: z.string(),
};
const WATCHABLE_TOOLS = {
    ssl: 'util/ssl', dns: 'util/dns', http: 'util/http', rdap: 'util/rdap', owasp: 'util/owasp', impersonation: 'util/impersonation',
};
const DEFAULT_WATCH_TOOLS = ['ssl', 'dns', 'http', 'rdap'];
// SYNC with GOLIVE_OUTPUT_SCHEMA in the monorepo remote registry.
const goliveOutputShape = {
    verdict: z.string().describe("'ready' | 'caution' | 'not_ready'"),
    passCount: z.number().optional(),
    warnCount: z.number().optional(),
    failCount: z.number().optional(),
    checks: z.array(z.object({ id: z.string(), status: z.string() })).optional(),
    reportUrl: z.string().describe('Human-facing interactive report on dechonet.com'),
};
function structuredFromInterp(data, url) {
    const interp = data?.interpretation;
    const sc = { status: String(interp?.status ?? 'unknown'), reportUrl: url };
    if (interp?.insight?.summary)
        sc.summary = String(interp.insight.summary);
    if (interp?.kpis?.length)
        sc.kpis = interp.kpis.map((k) => ({ label: String(k.label), value: String(k.value) }));
    if (interp?.issues?.length)
        sc.issues = interp.issues.map((i) => ({ severity: String(i.severity), key: String(i.key) }));
    if (interp?.actionItems?.length)
        sc.actions = interp.actionItems.map((a) => String(a));
    const grade = interp?.securityGrade ?? interp?.sslGrade;
    if (grade)
        sc.grade = String(grade);
    const score = interp?.securityScore ?? interp?.sslScore;
    if (typeof score === 'number')
        sc.score = score;
    return sc;
}
function formatResult(data, url) {
    const interp = data.interpretation;
    const lines = [];
    if (interp) {
        lines.push(`Status: ${interp.status.toUpperCase()}`);
        if (interp.title)
            lines.push(interp.title);
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
            if (interp.insight.detail)
                lines.push(`Detail: ${interp.insight.detail}`);
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
    }
    else {
        lines.push(rawJson);
    }
    if (url) {
        lines.push('');
        lines.push(`Full interactive report (share this link with the user): ${url}`);
    }
    const result = { content: [{ type: 'text', text: lines.join('\n') }] };
    if (url)
        result.structuredContent = structuredFromInterp(data, url);
    return result;
}
function errorResult(msg) {
    return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
}
// English category names + finding phrasings for owasp_check text output.
// SYNC with OWASP_CAT / OWASP_FINDING in the monorepo remote registry.
const OWASP_CAT = {
    headers: 'Secure Headers', a02: 'A02 Cryptographic Failures',
    a05: 'A05 Security Misconfiguration', a06: 'A06 Vulnerable & Outdated Components',
    exposed_files: 'Exposed Sensitive Files (A01/A05)',
};
const OWASP_FINDING = {
    header_missing: (d) => `Missing security header: ${d}`,
    header_partial: (d) => `Partially-configured header: ${d}`,
    info_leak: (d) => `Information disclosure: ${d}`,
    version_disclosed: (d) => `Component version disclosed: ${d}`,
    tls_unavailable: () => 'TLS not observable (no HTTPS or connection refused)',
    tls_weak_protocol: (d) => `Weak TLS protocol in use: ${d}`,
    chain_invalid: () => 'Certificate chain failed validation',
    cert_expired: (d) => `Certificate expired (${String(d ?? '').replace('-', '')} days ago)`,
    cert_expiring: (d) => `Certificate expiring in ${d} days`,
    no_hsts: () => 'No HSTS (transport-layer downgrade risk)',
    exposed_file: (d) => `Publicly readable sensitive file: ${d}`,
};
function formatOwasp(data, url) {
    const a = data?.assessment ?? {};
    const checks = a.checks ?? [];
    const notObs = a.notObservable ?? [];
    const evalCount = a.evaluatedCount ?? checks.length;
    const lines = [
        `=== OWASP Security Checkup: ${data?.host ?? ''} ===`,
        `Posture Grade: ${a.grade} (${a.score}/100)`,
        `Evaluated: ${evalCount} observable categor${evalCount === 1 ? 'y' : 'ies'} · ${notObs.length} require active/authenticated testing (out of scope)`,
        '',
    ];
    for (const c of checks) {
        lines.push(`[${String(c.status).toUpperCase()}] ${OWASP_CAT[c.id] ?? c.code}`);
        if (c.findings?.length) {
            for (const f of c.findings) {
                const fn = OWASP_FINDING[f.key];
                lines.push(`  - ${fn ? fn(f.detail) : f.key}`);
            }
        }
        else {
            lines.push('  - no issues found');
        }
    }
    lines.push('');
    lines.push(`Out of scope (not externally observable): ${notObs.map((n) => n.code).join(', ')}`);
    lines.push('');
    lines.push(`Full interactive report (share this link with the user): ${url}`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: {
            grade: String(a.grade), score: Number(a.score),
            checks: checks.map((c) => ({ code: c.code, status: c.status, findingCount: c.findings?.length ?? 0 })),
            notObservable: notObs.map((n) => n.code),
            reportUrl: url,
        },
    };
}
// SYNC with IMP_CAT / IMP_FINDING in the monorepo remote registry.
const IMP_CAT = {
    typosquat: 'Typosquat / Lookalike Domains', subdomains: 'Exposed Operational Subdomains', wildcard: 'Wildcard Certificate',
};
const IMP_FINDING = {
    lookalike_registered: (d) => `Registered lookalike domain: ${d} (verify ownership)`,
    lookalike_same_operator: (d) => `Lookalike on the domain's own nameservers/IP: ${d} (likely a defensive registration — not counted)`,
    risky_subdomain: (d) => `Exposed subdomain: ${d}`,
    wildcard_cert: () => 'A wildcard certificate (*.domain) has been issued',
};
function formatImpersonation(data, url) {
    const a = data?.assessment ?? {};
    const checks = a.checks ?? [];
    const lines = [
        `=== Brand Impersonation Exposure: ${data?.host ?? ''} ===`,
        `Exposure Grade: ${a.grade} (${a.score}/100, higher = less exposed)`,
        `Third-party lookalike domains: ${a.typosquatCount ?? 0} · Exposed subdomains: ${a.riskySubdomainCount ?? 0} · Wildcard cert: ${a.wildcard ? 'yes' : 'no'}`,
        'NOTE: a registered lookalike is not proof of impersonation — it may be a legitimate third party. Verify ownership.',
        '',
    ];
    for (const c of checks) {
        lines.push(`[${String(c.status).toUpperCase()}] ${IMP_CAT[c.id] ?? c.id}`);
        if (c.findings?.length) {
            for (const f of c.findings) {
                const fn = IMP_FINDING[f.key];
                lines.push(`  - ${fn ? fn(f.detail) : f.key}`);
            }
        }
        else {
            lines.push('  - no exposure found');
        }
    }
    lines.push('');
    lines.push(`Full interactive report (share this link with the user): ${url}`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: {
            grade: String(a.grade), score: Number(a.score),
            typosquatCount: Number(a.typosquatCount ?? 0), riskySubdomainCount: Number(a.riskySubdomainCount ?? 0),
            wildcard: !!a.wildcard, reportUrl: url,
        },
    };
}
// SYNC with formatDomainChanges in the monorepo remote registry.
function formatDomainChanges(data, url) {
    const lines = [`=== Domain Changes: ${data?.domain ?? ''} ===`];
    const changes = data?.changes ?? [];
    const tools = data?.watchedTools ?? [];
    const hLookups = data?.history?.lookups ?? [];
    const hChanges = data?.history?.changes ?? [];
    if (!data?.watched) {
        lines.push('');
        lines.push('This domain is NOT under a DechoNet daily watch.');
        lines.push('Call watch_domain to start one — from then on every daily check that finds a change is recorded here.');
    }
    else {
        lines.push(`Monitored tools: ${tools.map((t) => t.endpoint).join(', ') || '(none)'}`);
        lines.push('');
        if (changes.length === 0) {
            lines.push('No changes recorded by the daily watch yet — the domain has been stable.');
        }
        else {
            lines.push('Recorded changes from daily monitoring (newest first):');
            for (const c of changes)
                lines.push(`  [${c.changedAt ?? ''}] ${c.endpoint ?? ''} ${c.kind}: ${c.summary}`);
        }
    }
    // Lookup-to-lookup diff: stored snapshots from previous lookups by anyone
    // (agent or human) — available even without a watch.
    lines.push('');
    if (hLookups.length === 0) {
        lines.push('No previous DechoNet lookups are stored for this domain, so there is nothing to compare against yet. Run security_scan (or the specific tools) now; the next call to domain_changes will report what moved since today.');
    }
    else {
        const paired = hLookups.filter((l) => l.previousSeenAt);
        lines.push(`Stored lookups: ${hLookups.map((l) => `${l.endpoint} (last ${String(l.lastSeenAt ?? '').slice(0, 10)})`).join(', ')}`);
        if (paired.length === 0) {
            lines.push('Each tool has been looked up only once so far — no earlier snapshot to compare against. Re-run the relevant tool later and this will report the difference.');
        }
        else if (hChanges.length === 0) {
            lines.push(`Compared the last two lookups for ${paired.length} tool(s): nothing meaningful changed (volatile values like latency and countdowns are ignored).`);
        }
        else {
            lines.push('Changes between the last two lookups (newest first):');
            for (const c of hChanges)
                lines.push(`  ${c.endpoint ?? ''} ${c.kind}: ${c.summary}  (${String(c.since ?? '').slice(0, 10)} → ${String(c.changedAt ?? '').slice(0, 10)})`);
        }
    }
    lines.push('');
    lines.push(`Manage monitoring for this domain (share with the user): ${url}`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: {
            domain: String(data?.domain ?? ''),
            watched: !!data?.watched,
            changeCount: changes.length,
            changes: changes.map((c) => ({ endpoint: String(c.endpoint ?? ''), kind: String(c.kind ?? ''), summary: String(c.summary ?? ''), changedAt: String(c.changedAt ?? '') })),
            historyChangeCount: hChanges.length,
            historyChanges: hChanges.map((c) => ({ endpoint: String(c.endpoint ?? ''), kind: String(c.kind ?? ''), summary: String(c.summary ?? ''), since: String(c.since ?? ''), changedAt: String(c.changedAt ?? '') })),
            reportUrl: url,
        },
    };
}
// SYNC with formatWatchDomain in the monorepo remote registry.
function formatWatchDomain(domain, results, origin) {
    const okOnes = results.filter((r) => r.url);
    const failed = results.filter((r) => !r.url);
    const lines = [`=== Watch started: ${domain} ===`];
    if (okOnes.length) {
        lines.push(`DechoNet now re-checks this domain every day for: ${okOnes.map((r) => r.tool).join(', ')}.`);
        lines.push('Each check compares against the previous snapshot; grade drops, new issues, certificate renewals and DNS drift are recorded as changes.');
        lines.push('');
        for (const r of okOnes)
            lines.push(`  ${r.tool}: ${origin}${r.url}`);
    }
    if (failed.length) {
        lines.push('');
        lines.push(`Could not start: ${failed.map((r) => `${r.tool} (${r.error ?? 'error'})`).join(', ')}`);
    }
    lines.push('');
    lines.push('Next time this domain comes up, call domain_changes first — it will report what changed since today.');
    lines.push(`Monitoring overview for the user: ${origin}/pro?src=mcp-report`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: {
            domain,
            watches: okOnes.map((r) => ({ tool: r.tool, endpoint: r.endpoint, url: `${origin}${r.url}` })),
            failed: failed.map((r) => r.tool),
            reportUrl: `${origin}/pro?src=mcp-report`,
        },
        ...(okOnes.length === 0 ? { isError: true } : {}),
    };
}
// SYNC with GOLIVE_* maps in the monorepo remote registry.
const GOLIVE_CK = {
    dns_resolves: 'DNS Resolution', dns_propagated: 'DNS Propagation',
    tls_ready: 'SSL/TLS Readiness', https_reachable: 'HTTPS Reachability', domain_not_expiring: 'Domain Expiry',
};
const GOLIVE_FINDING = {
    no_dns: () => 'No A/AAAA record — the domain does not resolve',
    no_propagation: () => 'No value resolved from any resolver',
    propagating: () => 'Resolvers disagree — still propagating, re-check shortly',
    tls_unavailable: () => 'HTTPS certificate could not be observed',
    chain_invalid: () => 'Certificate chain failed validation',
    cert_expired: () => 'SSL certificate has expired',
    cert_expiring: (d) => `SSL certificate expiring in ${d} days`,
    unreachable: (d) => `Site could not be reached (status ${d ?? '—'})`,
    http_error_status: (d) => `Site returns an error status (${d})`,
    no_https: () => 'Final URL is not HTTPS — check the HTTPS redirect',
    domain_expired: () => 'Domain registration has expired',
    domain_expiring: (d) => `Domain registration expiring in ${d} days`,
};
const GOLIVE_VERDICT = { ready: 'READY', caution: 'CAUTION', not_ready: 'NOT READY' };
function formatGolive(data, url) {
    const a = data?.assessment ?? {};
    const checks = a.checks ?? [];
    const lines = [
        `=== Go-Live Readiness: ${data?.host ?? ''} ===`,
        `Verdict: ${GOLIVE_VERDICT[a.verdict] ?? String(a.verdict ?? '').toUpperCase()}`,
        `${checks.length} checks — ${a.passCount ?? 0} pass · ${a.warnCount ?? 0} caution · ${a.failCount ?? 0} fail`,
        '',
    ];
    for (const c of checks) {
        lines.push(`[${String(c.status).toUpperCase()}] ${GOLIVE_CK[c.id] ?? c.id}`);
        if (c.findings?.length) {
            for (const f of c.findings) {
                const fn = GOLIVE_FINDING[f.key];
                lines.push(`  - ${fn ? fn(f.detail) : f.key}`);
            }
        }
    }
    lines.push('');
    lines.push(`Full interactive report (share this link with the user): ${url}`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: {
            verdict: String(a.verdict ?? ''),
            passCount: Number(a.passCount ?? 0), warnCount: Number(a.warnCount ?? 0), failCount: Number(a.failCount ?? 0),
            checks: checks.map((c) => ({ id: c.id, status: c.status })),
            reportUrl: url,
        },
    };
}
export const tools = [
    {
        name: 'dns_lookup',
        title: 'DNS Lookup',
        outputSchema: interpOutputShape,
        annotations: annotate('DNS Lookup'),
        description: 'Query DNS records (A, AAAA, MX, TXT, NS, SOA, CAA) for a domain and validate email-related records, including DNSSEC presence and SPF/DMARC syntax, returning severity-rated diagnostics. ' +
            'Use this for a single authoritative answer about one domain. Use dns_propagation instead when you need to compare answers across multiple global resolvers (e.g., right after a change), or email_auth for a full SPF/DKIM/DMARC deliverability assessment. ' +
            'Read-only; requires no API key or authentication; subject to rate limiting. Returns a text report: status, KPI summary, detected issues, and recommended actions.',
        schema: {
            domain: z.string().describe("Registrable domain or hostname to query, without scheme or path (e.g., 'example.com' or 'mail.example.com'). Do not include 'http://' or a trailing slash."),
        },
        handler: async ({ domain }) => {
            try {
                return formatResult(await callApi(`/api/util/dns?query=${enc(domain)}`), reportUrl('dns', 'query', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'ssl_check',
        title: 'SSL Certificate Check',
        outputSchema: interpOutputShape,
        annotations: annotate('SSL Certificate Check'),
        description: "Inspect a host's served TLS/SSL certificate and connection: expiry date, issuer, SAN list, chain integrity, TLS version, and HSTS, returning an A+ to F grade weighted by certificate validity (40%), TLS version (25%), chain trust (15%), and HSTS (20%). " +
            'Use this to diagnose certificate or HTTPS-handshake problems for one host. Use http_security instead to audit response security headers, or security_scan for an all-in-one domain report. ' +
            'Read-only: it completes a TLS handshake but sends no application data; requires no API key; rate-limited. Returns a text report: grade, expiry/issuer KPIs, issues, and actions.',
        schema: {
            host: z.string().describe("Hostname to inspect, without scheme (e.g., 'example.com'). The host portion of a pasted URL is also accepted."),
            port: z.number().default(443).describe('TCP port for the TLS handshake. Defaults to 443 (standard HTTPS); set this only for a non-standard HTTPS port such as 8443.'),
        },
        handler: async ({ host, port }) => {
            try {
                return formatResult(await callApi(`/api/util/ssl?host=${enc(host)}&port=${port}`), reportUrl('ssl', 'host', host));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'http_security',
        title: 'HTTP Security Headers Audit',
        outputSchema: interpOutputShape,
        annotations: annotate('HTTP Security Headers Audit'),
        description: "Follow a URL's HTTP redirect chain and audit response security headers (CSP, HSTS, X-Frame-Options, COOP, CORP, COEP, Permissions-Policy), grading A+ to F and flagging information leaks such as server-version disclosure. " +
            'Use this for HTTP-layer/header posture. Use ssl_check instead for certificate or TLS-handshake issues, or security_scan for a full domain report. ' +
            'Read-only (an HTTP GET-style probe that sends no payload); requires no API key; rate-limited. Returns a text report: grade, header findings, redirect trace, issues, and actions.',
        schema: {
            url: z.string().describe("Full URL including scheme (e.g., 'https://example.com/path'). If the scheme is omitted, https:// is assumed. Redirects are followed starting from this URL."),
        },
        handler: async ({ url }) => {
            try {
                return formatResult(await callApi(`/api/util/http?url=${enc(url)}`), reportUrl('http', 'url', url));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'email_auth',
        title: 'Email Authentication Check',
        outputSchema: interpOutputShape,
        annotations: annotate('Email Authentication Check'),
        description: "Assess a domain's email authentication and deliverability posture: MX records, SPF, DMARC, DKIM (probes 15 common selectors), BIMI, MTA-STS, TLS-RPT, and DANE, plus a blacklist check across all MX hosts, returning a 0-100 deliverability score. " +
            'Use this for a full sending/receiving readiness review of a domain. Use dns_lookup instead if you only need raw TXT/MX records, or email_header_analysis to diagnose a specific message that was already sent. ' +
            'Read-only; requires no API key; rate-limited. Returns a text report: score, per-mechanism KPIs, issues, and actions.',
        schema: {
            domain: z.string().describe("Email domain to assess — the part after '@' (e.g., 'example.com'). An IP address is also accepted for reverse/PTR-based checks."),
        },
        handler: async ({ domain }) => {
            try {
                return formatResult(await callApi(`/api/util/email?query=${enc(domain)}`), reportUrl('email', 'query', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'port_scan',
        title: 'Open Port Scan',
        outputSchema: interpOutputShape,
        annotations: annotate('Open Port Scan'),
        description: 'Probe a host for a fixed set of common TCP ports (HTTP, HTTPS, SSH, FTP, SMTP, DNS, and common databases) and report which are open, the service name, and the response time. ' +
            'BEHAVIOR: this makes an ACTIVE TCP connection to the target. It is non-intrusive — a connect probe only; it does not authenticate, send exploits, or transfer data — and changes nothing on the target (read-only), but the connection is visible in the target\'s logs, so only scan hosts you own or are explicitly authorized to test. ' +
            'Use this to confirm which services are exposed. Use ssl_check or http_security instead to assess a specific service\'s configuration. Requires no API key; rate-limited. Returns a per-port open/closed list with service names.',
        schema: {
            host: z.string().describe("Hostname or IP to probe (e.g., 'example.com' or '203.0.113.10'). A 'host:port' form is accepted to hint a specific port. Only supply targets you own or are authorized to test."),
        },
        handler: async ({ host }) => {
            try {
                return formatResult(await callApi(`/api/util/port?host=${enc(host)}`), reportUrl('port', 'host', host));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'dns_propagation',
        title: 'DNS Propagation Check',
        outputSchema: interpOutputShape,
        annotations: annotate('DNS Propagation Check'),
        description: 'Query one DNS record across 8+ global public resolvers (Google, Cloudflare, Quad9, OpenDNS, and more) simultaneously and report which resolvers return stale versus updated values. ' +
            'Use this after changing a record to confirm worldwide propagation. Use dns_lookup instead for a single authoritative answer with SPF/DMARC validation. ' +
            'Read-only; requires no API key; rate-limited. Returns per-resolver values and a consistency verdict.',
        schema: {
            domain: z.string().describe("Domain whose record to compare across resolvers (e.g., 'example.com'), without scheme or path."),
            type: z.enum(['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS']).default('A').describe('DNS record type to compare across resolvers. Defaults to A (IPv4 address), the most common propagation check.'),
        },
        handler: async ({ domain, type }) => {
            try {
                return formatResult(await callApi(`/api/util/propagation?domain=${enc(domain)}&type=${type}`), reportUrl('propagation', 'domain', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'reverse_dns',
        title: 'Reverse DNS (PTR) Lookup',
        outputSchema: interpOutputShape,
        annotations: annotate('Reverse DNS (PTR) Lookup'),
        description: "Resolve the PTR (reverse DNS) record for an IPv4 or IPv6 address and verify forward-confirmed reverse DNS (FCrDNS) by checking that the PTR hostname resolves back to the same IP. Infers the hosting provider from PTR naming patterns. " +
            'Use this to validate mail-server rDNS or identify a single IP\'s host. Use asn_lookup instead for network/BGP ownership of the IP. ' +
            'Read-only; requires no API key; rate-limited. Returns the PTR hostname, FCrDNS pass/fail, and a provider guess.',
        schema: {
            ip: z.string().describe("IP address to reverse-resolve, IPv4 or IPv6 (e.g., '8.8.8.8' or '2001:4860:4860::8888'). Must be an IP, not a hostname."),
        },
        handler: async ({ ip }) => {
            try {
                return formatResult(await callApi(`/api/util/reverse-dns?query=${enc(ip)}`), reportUrl('reverse-dns', 'query', ip));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'asn_lookup',
        title: 'ASN / BGP Lookup',
        outputSchema: interpOutputShape,
        annotations: annotate('ASN / BGP Lookup'),
        description: 'Look up Autonomous System (ASN) / BGP information for an IP address or AS number: the network operator, announced prefixes, abuse contact, and a classification (cloud, CDN, ISP, hosting, or enterprise). ' +
            'Use this to identify who runs a network or whether an IP is cloud/CDN-hosted. Use reverse_dns instead for the host-level PTR name of a single IP. ' +
            'Read-only; requires no API key; rate-limited. Returns operator, prefixes, classification, and abuse contact.',
        schema: {
            query: z.string().describe("An IP address (e.g., '1.1.1.1') or an AS number in 'AS####' form (e.g., 'AS13335')."),
        },
        handler: async ({ query }) => {
            try {
                return formatResult(await callApi(`/api/util/asn?query=${enc(query)}`), reportUrl('asn', 'query', query));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'whois_lookup',
        title: 'WHOIS / RDAP Domain Lookup',
        outputSchema: interpOutputShape,
        annotations: annotate('WHOIS / RDAP Domain Lookup'),
        description: 'Retrieve domain registration data via RDAP (with WHOIS fallback): registrar, creation/expiry/update dates, nameservers, and EPP status flags, highlighting risk states such as clientHold and pendingDelete. ' +
            'Use this for ownership, lifecycle, and expiry questions about a registered domain. Use dns_lookup instead for live DNS records, or reverse_dns/asn_lookup for IP-level ownership. ' +
            'Read-only; requires no API key; rate-limited. Returns registrar, key dates, nameservers, and status flags.',
        schema: {
            domain: z.string().describe("Registered domain name to look up (e.g., 'example.com'). A subdomain is normalized to its registrable domain."),
        },
        handler: async ({ domain }) => {
            try {
                return formatResult(await callApi(`/api/util/rdap?query=${enc(domain)}`), reportUrl('rdap', 'query', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'subdomain_discovery',
        title: 'Subdomain Discovery',
        outputSchema: interpOutputShape,
        annotations: annotate('Subdomain Discovery'),
        description: 'Enumerate the subdomains of a domain from Certificate Transparency logs — fully passive (no packets are sent to the target; CT logs are public records of every TLS certificate ever issued). Flags operational-looking names (dev, staging, admin, vpn, legacy) and wildcard certificates, because forgotten subdomains are a common takeover path. ' +
            "Use this as the first recon step to map a domain's attack surface. Use dns_lookup to check whether a discovered name still resolves, or lookalike_domains for typosquat variants of the domain name itself. " +
            'Read-only; requires no API key; rate-limited. Returns the subdomain count, risky-name count, wildcard flag, and the hostname list.',
        schema: {
            domain: z.string().describe("Registrable domain to enumerate (e.g., 'example.com'), without scheme or path. Subdomains found in CT logs for this domain are returned."),
        },
        handler: async ({ domain }) => {
            try {
                return formatResult(await callApi(`/api/util/subdomains?query=${enc(domain)}`), reportUrl('subdomains', 'query', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'lookalike_domains',
        title: 'Lookalike Domain Check',
        outputSchema: interpOutputShape,
        annotations: annotate('Lookalike Domain Check'),
        description: 'Generate the typosquat/lookalike variants of a domain that phishers actually register — homoglyph swaps (l→1, o→0, rn→m), TLD swaps (.com→.co), character omissions, transpositions, repetitions, hyphenations — and check which of them are currently registered (live NS delegation via DoH). ' +
            'Use this to assess brand-impersonation and phishing exposure for a domain the user is responsible for. A registered variant is NOT proof of abuse (it may be an unrelated legitimate site) — follow up with whois_lookup on each hit for its owner and registration date. ' +
            'Read-only; requires no API key; rate-limited. Returns generated/checked counts and the registered variants with the technique that produced each.',
        schema: {
            domain: z.string().describe("Domain to protect (e.g., 'example.com'), without scheme or path. Variants of its label and TLD are generated and checked."),
        },
        handler: async ({ domain }) => {
            try {
                return formatResult(await callApi(`/api/util/lookalike?query=${enc(domain)}`), reportUrl('lookalike', 'query', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'ip_info',
        title: 'My IP Info',
        outputSchema: interpOutputShape,
        annotations: annotate('My IP Info'),
        description: "Report information about the caller's own public IP as seen by the server: IPv4/IPv6 address, ISP, ASN, approximate geolocation, and proxy/VPN heuristics. " +
            "Takes no input — it reflects the egress IP of THIS MCP server's network, which is usually NOT the end user's IP. Use this to discover the server's outbound IP or test connectivity. To inspect a specific, known IP instead, use asn_lookup or reverse_dns. " +
            'Read-only; requires no API key; rate-limited.',
        schema: {},
        handler: async () => {
            try {
                return formatResult(await callApi('/api/util/ip'), reportUrl('ip'));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'email_header_analysis',
        title: 'Email Header Analysis',
        outputSchema: interpOutputShape,
        annotations: annotate('Email Header Analysis'),
        description: 'Parse raw email headers to reconstruct the delivery path (each Received hop in order), extract SPF/DKIM/DMARC authentication results, measure per-hop delays, and flag unencrypted (non-TLS) hops. ' +
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
                const json = await res.json();
                if (!json.ok)
                    throw new Error(json.error?.message || 'API error');
                return formatResult(json.data, reportUrl('email-header'));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'subnet_calc',
        title: 'IPv4 Subnet Calculator',
        outputSchema: subnetOutputShape,
        annotations: annotate('IPv4 Subnet Calculator', false),
        description: 'Compute IPv4 subnet details from CIDR notation entirely locally — no network call: network and broadcast addresses, usable host range, total usable hosts, subnet mask, and wildcard mask. /31 and /32 are handled per RFC 3021 (point-to-point / single host). ' +
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
                if (!ip || isNaN(prefix) || prefix < 0 || prefix > 32)
                    throw new Error('Invalid CIDR notation');
                const parts = ip.split('.').map(Number);
                if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255))
                    throw new Error('Invalid IP');
                const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
                const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
                const network = (ipNum & mask) >>> 0;
                const broadcast = (network | ~mask) >>> 0;
                const firstHost = prefix >= 31 ? network : (network + 1) >>> 0;
                const lastHost = prefix >= 31 ? broadcast : (broadcast - 1) >>> 0;
                const totalHosts = prefix >= 31 ? (prefix === 32 ? 1 : 2) : Math.pow(2, 32 - prefix) - 2;
                const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
                const toMask = (m) => toIp(m);
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
                const url = reportUrl('subnet', 'query', cidr);
                const text = Object.entries(result).map(([k, v]) => `${k}: ${v}`).join('\n') +
                    `\n\nFull interactive report (share this link with the user): ${url}`;
                return { content: [{ type: 'text', text }], structuredContent: { ...result, reportUrl: url } };
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'security_scan',
        title: 'Full Domain Security Scan',
        outputSchema: scanOutputShape,
        annotations: annotate('Full Domain Security Scan'),
        description: 'One-shot comprehensive audit of a domain: runs DNS, SSL, HTTP headers, email auth, port scan, DNS propagation, reverse DNS, and ASN/RDAP checks in parallel, then computes a 0-100 Health Score with an A-F grade and a prioritized action list. ' +
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
                const get = (r) => r.status === 'fulfilled' ? r.value : null;
                const results = {
                    dns: get(dns), ssl: get(ssl), http: get(http), email: get(email),
                    port: get(port), propagation: get(propagation), rdap: get(rdap),
                };
                // Extract origin IP for rDNS + ASN
                const aRecord = results.dns?.raw?.records?.find((r) => r.type === 'A');
                if (aRecord) {
                    const [rdns, asn] = await Promise.allSettled([
                        callApi(`/api/util/reverse-dns?query=${enc(aRecord.value)}`),
                        callApi(`/api/util/asn?query=${enc(aRecord.value)}`),
                    ]);
                    results.reverseDns = get(rdns);
                    results.asn = get(asn);
                }
                // Calculate health score
                const weights = { rdap: 10, dns: 18, ssl: 18, http: 14, email: 14, propagation: 8, port: 8, reverseDns: 5, asn: 5 };
                let score = 100;
                const areas = [];
                for (const [key, weight] of Object.entries(weights)) {
                    const r = results[key];
                    if (!r) {
                        score -= weight;
                        areas.push(`${key}: FAILED (-${weight})`);
                        continue;
                    }
                    const interp = r.interpretation;
                    if (!interp)
                        continue;
                    const criticals = interp.issues?.filter((i) => i.severity === 'critical')?.length || 0;
                    const warnings = interp.issues?.filter((i) => i.severity === 'warning')?.length || 0;
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
                const allActions = [];
                for (const r of Object.values(results)) {
                    if (r?.interpretation?.actionItems)
                        allActions.push(...r.interpretation.actionItems);
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
                        if (r.interpretation?.insight?.summary)
                            lines.push(`Summary: ${r.interpretation.insight.summary}`);
                    }
                }
                const url = reportUrl('all', 'query', domain);
                lines.push('');
                lines.push(`Full interactive report (share this link with the user): ${url}`);
                return {
                    content: [{ type: 'text', text: lines.join('\n') }],
                    structuredContent: {
                        score, grade,
                        areas: areas.map((a) => { const i = a.indexOf(': '); return { area: a.slice(0, i), verdict: a.slice(i + 2) }; }),
                        ...(allActions.length > 0 ? { actions: allActions.slice(0, 5) } : {}),
                        reportUrl: url,
                    },
                };
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'owasp_check',
        title: 'OWASP Security Checkup',
        outputSchema: owaspOutputShape,
        annotations: annotate('OWASP Security Checkup'),
        description: "Assess a domain's OWASP posture from EXTERNAL OBSERVATION only: the OWASP Secure Headers Project plus the externally observable Top 10 subset — A02 Cryptographic Failures (TLS/cert), A05 Security Misconfiguration (header/info leaks), and A06 Vulnerable & Outdated Components (version disclosure) — returning an A+ to F grade. " +
            'Scope: A01 (Access Control), A03 (Injection), A04, A07 (Authentication), A08, A09 and A10 (SSRF) are not checked — they need authenticated access or active/injection testing, so the result lists them as out-of-scope rather than "pass". Present the result as an external-posture check, not a full OWASP Top 10 assessment. ' +
            'Unlike security_scan this is fully PASSIVE (a normal HTTP GET plus a public CT-log lookup, no port scan), so it is safe and lawful to run on domains you do not own. Use http_security or ssl_check for depth on one layer. ' +
            'Read-only; requires no API key; rate-limited. Returns a text report: grade, per-category findings, the out-of-scope list, and a shareable report link.',
        schema: {
            host: z.string().describe("Hostname to assess, without scheme (e.g., 'example.com'). The host portion of a pasted URL is also accepted."),
        },
        handler: async ({ host }) => {
            try {
                return formatOwasp(await callApi(`/api/util/owasp?host=${enc(host)}`), reportUrl('owasp', 'host', host));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'impersonation_exposure',
        title: 'Brand Impersonation Exposure',
        outputSchema: impOutputShape,
        annotations: annotate('Brand Impersonation Exposure'),
        description: "Assess how exposed a domain is to brand impersonation and phishing, PASSIVELY: live typosquat/lookalike domains (homoglyph, omission, transposition, TLD swap) that actually resolve, operational subdomains (dev/staging/admin) exposed in CT logs, and whether a wildcard certificate exists — returning an A+ (low exposure) to F (high exposure) grade. " +
            'Framing: a registered lookalike domain is not proof of impersonation — it may be a legitimate third party or the owner\'s own — so report it as exposure to verify, not as an accusation against that domain. ' +
            'Fully passive: public DNS delegation checks plus public CT-log queries, sending nothing to the target or the lookalike domains, so it is safe and lawful to run. Use lookalike_domains or subdomain_discovery for the raw per-tool detail. ' +
            'Read-only; requires no API key; rate-limited. Returns a text report: grade, counts, per-category findings, and a shareable report link.',
        schema: {
            domain: z.string().describe("Registrable domain to assess for impersonation exposure (e.g., 'example.com'). Scheme and path are stripped."),
        },
        handler: async ({ domain }) => {
            try {
                return formatImpersonation(await callApi(`/api/util/impersonation?query=${enc(domain)}`), reportUrl('impersonation', 'query', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'domain_changes',
        title: 'Domain Change History',
        outputSchema: domainChangesOutputShape,
        annotations: annotate('Domain Change History'),
        description: 'Report what has changed for a domain over time — the security regressions and drift that DechoNet\'s daily monitoring has recorded across every watch on the domain (SSL grade, headers, DNS, OWASP posture, impersonation exposure, etc.). ' +
            'Use this to answer "what changed on my domain since yesterday/last week?" — a question that requires persistent snapshots and therefore cannot be reconstructed from a single live lookup. When a domain you have looked at before comes up again, start with this tool. ' +
            'Two sources: (a) the daily watch timeline if the domain is watched (start one with watch_domain), and (b) even without a watch, the difference between the last two stored lookups of each tool — so a second lookup already yields a comparison. The point-in-time tools (security_scan, owasp_check, ssl_check) give the current state instead. ' +
            'Read-only; requires no API key; rate-limited. Returns the monitored tools, a newest-first change timeline, lookup-to-lookup changes, and a link to manage monitoring.',
        schema: {
            domain: z.string().describe("Domain whose recorded change history to fetch (e.g., 'example.com'). Scheme and path are stripped."),
        },
        handler: async ({ domain }) => {
            try {
                return formatDomainChanges(await callApi(`/api/util/changes?query=${enc(domain)}`), 'https://dechonet.com/pro?src=mcp-report');
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'watch_domain',
        title: 'Watch a Domain (daily re-check)',
        outputSchema: watchDomainOutputShape,
        annotations: { title: 'Watch a Domain (daily re-check)', readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        description: 'Start (or reuse) a daily DechoNet watch on a domain so that changes are recorded over time — SSL grade/issuer/expiry, DNS records, HTTP security headers, domain registration, and optionally OWASP posture and impersonation exposure. ' +
            'Use this once when the user cares about a domain beyond a one-off check (their own domain, a client, a vendor, a target under investigation). After this, domain_changes answers "what changed since last time?" from real daily snapshots. ' +
            'Not read-only (it creates a watch record) but idempotent: watching an already-watched domain returns the existing watch. No account, no email, no PII — a watch is keyed by domain+tool and its history page is a public unguessable URL you can share with the user. Rate-limited (a few watches per minute).',
        schema: {
            domain: z.string().describe("Registered domain to watch (e.g., 'example.com'). Scheme and path are stripped."),
            tools: z.array(z.enum(['ssl', 'dns', 'http', 'rdap', 'owasp', 'impersonation'])).optional().describe("Which checks to re-run daily. Default ['ssl','dns','http','rdap'] (certificate, DNS, security headers, registration). Add 'owasp' and/or 'impersonation' for posture and brand-exposure tracking."),
        },
        handler: async ({ domain, tools }) => {
            const clean = String(domain ?? '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').split('/')[0];
            const chosen = (Array.isArray(tools) && tools.length ? tools : DEFAULT_WATCH_TOOLS).map(String).filter((t) => WATCHABLE_TOOLS[t]);
            if (!clean || chosen.length === 0)
                return errorResult('Provide a domain and at least one known tool.');
            const results = [];
            for (const tool of chosen) {
                const endpoint = WATCHABLE_TOOLS[tool];
                try {
                    const data = await postApi('/api/watch', { endpoint, target: clean });
                    results.push({ tool, endpoint, url: data?.url });
                }
                catch (e) {
                    results.push({ tool, endpoint, error: e.message });
                }
            }
            return formatWatchDomain(clean, results, 'https://dechonet.com');
        },
    },
    {
        name: 'golive_check',
        title: 'Go-Live Readiness Checklist',
        outputSchema: goliveOutputShape,
        annotations: annotate('Go-Live Readiness Checklist'),
        description: 'Check whether a domain is ready to launch or migrate — a go/no-go verdict over five essentials: DNS resolves to an IP, has propagated consistently across global resolvers, SSL/TLS is ready, the site is reachable over HTTPS, and the domain registration is not about to expire. ' +
            'Use this right before flipping DNS to a new server, or to confirm a migration has landed. It answers "can I switch over yet?"; use security_scan for a security posture grade or the individual tools for depth. Any failing essential yields not_ready; only cautions yields caution; all clear yields ready. ' +
            'Read-only (a passive multi-probe, though it does resolve and fetch the domain); requires no API key; rate-limited. Returns the verdict, per-check statuses, and a shareable report link.',
        schema: {
            domain: z.string().describe("Domain to check for launch/migration readiness (e.g., 'example.com'). Scheme and path are stripped."),
        },
        handler: async ({ domain }) => {
            try {
                return formatGolive(await callApi(`/api/util/golive?query=${enc(domain)}`), reportUrl('golive', 'query', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
];
function enc(s) {
    return encodeURIComponent(s);
}
