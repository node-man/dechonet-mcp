import { z } from 'zod';
const BASE_URL = process.env.DECHONET_URL || 'https://dechonet.com';
const LOCALE = process.env.DECHONET_LOCALE || 'en';
// Optional free API key (account page): own rate-limit bucket; needed for infrastructure_pivot.
const API_KEY = (process.env.DECHONET_API_KEY ?? '').trim();
async function callApi(path) {
    const res = await fetch(`${BASE_URL}${path}`, {
        headers: { 'User-Agent': 'DechoNet-MCP/1.0', 'Accept-Language': LOCALE, ...(API_KEY ? { Authorization: `Bearer ${API_KEY}` } : {}) },
    });
    const json = await res.json();
    if (!json.ok) {
        throw Object.assign(new Error(json.error?.message || `API error: ${res.status}`), { reason: json.error?.reason });
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
// History & pivot (plan E2): plain text for the agent + structuredContent.
function formatHistory(d) {
    const lines = [`=== Observed infrastructure history: ${d?.target ?? ''} ===`];
    if (!d?.observed)
        lines.push('DechoNet has no observations for this target yet. Run security_scan or dns_lookup now; later calls will show how its infrastructure changes.');
    for (const k of d?.kinds ?? []) {
        lines.push('', `${k.kind}:`);
        for (const v of k.values)
            lines.push(`  ${v.value}  (first ${String(v.firstSeen).slice(0, 10)} · last ${String(v.lastSeen).slice(0, 10)} · seen ${v.seen}×)`);
    }
    lines.push('', `Coverage: ${d?.note ?? ''}`);
    return { content: [{ type: 'text', text: lines.join('\n') }], structuredContent: { target: String(d?.target ?? ''), observed: !!d?.observed, kinds: d?.kinds ?? [], note: String(d?.note ?? '') } };
}
function formatPivot(d) {
    const lines = [`=== Targets seen with ${d?.kind} = ${d?.value} ===`, `${d?.total ?? 0}${d?.totalCapped ? '+' : ''} target(s) in DechoNet's observations.`];
    if (d?.sharedInfra)
        lines.push('Shared infrastructure — sharing it says nothing about common ownership; no list is given.');
    for (const t of d?.targets ?? [])
        lines.push(`  ${t.target}  (first ${String(t.firstSeen).slice(0, 10)} · last ${String(t.lastSeen).slice(0, 10)})`);
    if ((d?.targets?.length ?? 0) < (d?.total ?? 0) && !d?.sharedInfra)
        lines.push(`  … showing ${d.targets.length} (limit ${d.limit}; MCP·API Pro shows more).`);
    lines.push('', `Coverage: ${d?.note ?? ''}`);
    return { content: [{ type: 'text', text: lines.join('\n') }], structuredContent: { kind: String(d?.kind ?? ''), value: String(d?.value ?? ''), sharedInfra: !!d?.sharedInfra, total: Number(d?.total ?? 0), targets: d?.targets ?? [], note: String(d?.note ?? '') } };
}
// SYNC with HISTORY_OUTPUT_SCHEMA / PIVOT_OUTPUT_SCHEMA in the monorepo remote registry.
const historyOutputShape = {
    target: z.string(), observed: z.boolean(), note: z.string().optional(),
    kinds: z.array(z.object({ kind: z.string(), values: z.array(z.object({ value: z.string(), firstSeen: z.string(), lastSeen: z.string(), seen: z.number() })) })),
};
const pivotOutputShape = {
    kind: z.string(), value: z.string(), sharedInfra: z.boolean().optional(), total: z.number(), note: z.string().optional(),
    targets: z.array(z.object({ target: z.string(), firstSeen: z.string(), lastSeen: z.string() })),
};
// SYNC with WATCH_DOMAIN_OUTPUT_SCHEMA in the monorepo remote registry.
const watchDomainOutputShape = {
    domain: z.string(),
    watches: z.array(z.object({ tool: z.string(), endpoint: z.string().optional(), url: z.string().describe('Public change-history page for this watch') })).describe('One entry per tool now under a daily watch'),
    failed: z.array(z.string()).optional().describe('Tools that could not be watched (rate limit or error)'),
    reportUrl: z.string(),
};
const WATCHABLE_TOOLS = {
    ssl: 'util/ssl', dns: 'util/dns', http: 'util/http', rdap: 'util/rdap', owasp: 'util/owasp', impersonation: 'util/impersonation', pqc: 'util/pqc', exposure: 'util/exposure',
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
// SYNC with PQC_OUTPUT_SCHEMA in the monorepo remote registry.
const pqcOutputShape = {
    verdict: z.string().describe("'ready' | 'partial' | 'not_ready' | 'unknown'"),
    score: z.number().nullable().optional().describe('0-100 post-quantum readiness; null when inconclusive'),
    grade: z.string().nullable().optional(),
    keyExchange: z.string().nullable().optional().describe('Hybrid group accepted (e.g. X25519MLKEM768), null if none'),
    terminatedBy: z.string().nullable().optional().describe("'origin' or the CDN name whose edge answered"),
    tlsVersion: z.string().nullable().optional(),
    checks: z.array(z.object({ id: z.string(), status: z.string() })).optional(),
    reportUrl: z.string().describe('Human-facing interactive report on dechonet.com'),
};
// SYNC with the PQC maps in the monorepo remote registry.
const PQC_CK = {
    hybrid_kex: 'Hybrid post-quantum key exchange', kex_origin: 'Who provides it', tls13: 'TLS 1.3',
    cert_crypto: 'Certificate signatures', kr_algorithms: 'Korean PQC algorithms (KpqC)',
};
const PQC_FINDING = {
    hybrid_supported: (d) => `Accepted a handshake offering only ${d ?? 'X25519MLKEM768'}`,
    hybrid_missing: () => 'Refused a handshake offering only hybrid post-quantum groups (classical key exchange only)',
    cdn_can_enable: (d) => `TLS is terminated by ${d}; post-quantum key exchange can usually be enabled in the CDN settings`,
    hybrid_inconclusive: () => 'No clear accept or refuse (timeout or reset) — inconclusive, not a "no"',
    via_cdn: (d) => `Provided by the ${d} edge, not by the organisation's own server`,
    origin_direct: () => 'Provided by the server answering for this domain (no known CDN in front)',
    tls_old: (d) => `Negotiated ${d}; hybrid post-quantum key exchange requires TLS 1.3`,
    weak_classical: (d) => `Weak classical cryptography in the chain: ${d}`,
    pq_signature: (d) => `Post-quantum signature in the leaf certificate: ${d}`,
    classical_signature: (d) => `Leaf certificate: ${d} (tracked, not scored)`,
    kr_unobservable: () => 'NTRU+, SMAUG-T, HAETAE and AIMer have no standard TLS codepoints yet — not observable from outside',
    probe_unavailable: () => 'The post-quantum probe is unavailable right now',
    unreachable: () => 'Could not complete a TLS handshake on port 443',
};
const PQC_VERDICT = { ready: 'READY', partial: 'PARTIAL (CDN)', not_ready: 'NOT READY', unknown: 'UNKNOWN (inconclusive)' };
function formatPqc(data, url) {
    const a = data?.assessment ?? {};
    const r = data?.raw ?? {};
    const checks = a.checks ?? [];
    const lines = [
        `=== Post-Quantum TLS Readiness: ${data?.host ?? ''} ===`,
        `Verdict: ${PQC_VERDICT[a.verdict] ?? String(a.verdict ?? '').toUpperCase()}`,
        ...(a.score === null || a.score === undefined ? [] : [`Score: ${a.score}/100 (${a.grade})`]),
        '',
    ];
    for (const c of checks) {
        lines.push(`[${String(c.status).toUpperCase()}] ${PQC_CK[c.id] ?? c.id}`);
        for (const f of c.findings ?? []) {
            const fn = PQC_FINDING[f.key];
            lines.push(`  - ${fn ? fn(f.detail) : f.key}`);
        }
    }
    if (r.redirectsTo)
        lines.push('', `Note: ${data?.host ?? ''} redirects to ${r.redirectsTo}. Visitors land there and its result can differ — run pqc_readiness on ${r.redirectsTo} too.`);
    lines.push('');
    lines.push('Scope: public TLS endpoint on port 443 only — an external indicator, not a full PQC audit.');
    lines.push(`Full interactive report (share this link with the user): ${url}`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: {
            verdict: String(a.verdict ?? ''),
            score: typeof a.score === 'number' ? a.score : null,
            grade: a.grade ?? null,
            keyExchange: r.hybridKex === true ? String(r.group ?? 'X25519MLKEM768') : null,
            terminatedBy: r.connected ? String(r.cdn ?? 'origin') : null,
            tlsVersion: r.tlsVersion ?? null,
            checks: checks.map((c) => ({ id: c.id, status: c.status })),
            reportUrl: url,
        },
    };
}
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
    geo_variation: () => 'Resolvers get different addresses with a short TTL — geo-DNS / CDN load balancing, not an unfinished change',
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
const exposureOutputShape = {
    status: z.string().describe('bad | warn | ok | info'),
    found: z.number(), probed: z.number(),
    counts: z.record(z.number()).describe('hosts per category (devtool, api_docs, listing, admin, remote, staging, default_page, login, api, mail, web, …)'),
    issues: z.array(z.string()),
    reportUrl: z.string(),
};
const EXPOSURE_CATEGORY = {
    listing: 'directory listings', devtool: 'developer/ops tools (Jenkins, Grafana, phpMyAdmin …)', api_docs: 'API documentation open to anyone (Swagger UI, Redoc, GraphQL IDE, OpenAPI spec)', admin: 'admin screens open to anyone',
    remote: 'VPN / remote-access login pages', staging: 'staging / development servers', default_page: 'default web-server pages',
    login: 'login pages', api: 'API endpoints', mail: 'webmail', web: 'regular web pages', redirect: 'redirects elsewhere',
    error: 'errors / access denied (incl. IP-restricted)', no_web: 'no web answer', unresolved: 'not resolving', skipped: 'skipped (time budget)',
};
const EXPOSURE_ISSUE = {
    exposure_directory_listing: 'A directory listing is open — turn off listing on the web server.',
    exposure_devtool: 'Developer/ops tools face the internet — move them behind the VPN or restrict by IP.',
    exposure_api_docs: 'API documentation is public — the first map automated attack tools read. Put it behind a login or the internal network, and make sure every endpoint checks authorisation.',
    exposure_admin: 'An admin login opens from anywhere — add an IP allow-list or SSO/2FA in front of it.',
    exposure_remote_access: 'VPN/remote-access login pages are visible — keep firmware patched and require MFA.',
    exposure_staging: 'Staging/dev servers are public — restrict access or take them down.',
    exposure_default_page: 'Default web-server pages are visible — likely unused servers; clean them up.',
    exposure_login: 'Login pages exist — fine if expected; confirm 2FA and rate limiting.',
    exposure_http_only: 'Some hosts answer over plain HTTP only (Chrome 154+, October 2026, shows visitors a warning screen first).',
    exposure_cert_error: 'Some hosts fail HTTPS with a certificate error.',
};
const EXPOSURE_ORDER = ['listing', 'devtool', 'api_docs', 'admin', 'remote', 'staging', 'default_page', 'login', 'api', 'mail', 'web', 'redirect', 'error', 'no_web', 'unresolved', 'skipped'];
function formatExposure(data, url) {
    const raw = data?.raw ?? {};
    const it = data?.interpretation ?? {};
    const counts = raw.counts ?? {};
    const lines = [`=== Exposed Admin Pages: ${raw.domain ?? ''} ===`, `Status: ${String(it.status ?? 'info').toUpperCase()} — checked ${raw.probed ?? 0} of ${raw.found ?? 0} known hosts${raw.truncated ? ' (risky-looking names first, capped at 40)' : ''}`, ''];
    for (const k of EXPOSURE_ORDER)
        if (counts[k])
            lines.push(`  ${counts[k]} × ${EXPOSURE_CATEGORY[k] ?? k}`);
    const issues = (it.issues ?? []).map((i) => String(i.key));
    if (issues.length) {
        lines.push('', 'What to do:');
        for (const k of issues)
            lines.push(`  - ${EXPOSURE_ISSUE[k] ?? k}`);
    }
    lines.push('', 'Public view: counts and verdict only — which host shows what is shown to the verified domain owner on the web page (DNS TXT record), together with a sensitive-file check (.env, .git …). Each host is opened once (first page only); no logins, path guessing or exploits. Hosts never seen in Certificate Transparency are not covered.');
    lines.push(`Full interactive report (the owner can verify there): ${url}`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: { status: String(it.status ?? 'info'), found: Number(raw.found ?? 0), probed: Number(raw.probed ?? 0), counts, issues, reportUrl: url },
    };
}
const phishingOutputShape = {
    verdict: z.string().describe('danger | suspicious | unreachable | official | no_signals | no_links'),
    links: z.array(z.object({ url: z.string(), finalUrl: z.string(), verdict: z.string(), ageDays: z.number().nullable(), signals: z.array(z.string()) })),
    reportUrl: z.string(),
};
const PHISHING_SIGNAL = {
    known_malicious: (d) => `listed on public phishing/malware feeds (${d ?? ''})`,
    apk_download: () => 'downloads an Android app (APK) — the classic smishing payload',
    brand_in_subdomain: (d) => `wears the real brand domain ${d ?? ''} inside a different domain`,
    brand_lookalike: (d) => `lookalike spelling of ${d ?? ''}`,
    brand_keyword: (d) => `carries a brand name but is not the official domain (${d ?? ''})`,
    domain_new: (d) => `domain registered only ${d ?? '?'} days ago`,
    domain_recent: (d) => `domain registered ${d ?? '?'} days ago`,
    punycode: () => 'internationalised (punycode) domain',
    ip_address: () => 'points to a bare IP address',
    tracked: () => 'already tracked by DechoNet as a possible brand impersonation',
    shortener: () => 'shortened link (real destination was hidden)',
    cheap_tld: (d) => `low-cost TLD common in phishing (.${d ?? ''})`,
    not_resolving: () => 'domain does not resolve right now',
    free_hosting: (d) => `on a free hosting / dynamic-DNS platform (${d ?? ''}) — not a warning by itself`,
    brand_account: (d) => `GitHub/GitLab account page named after ${d ?? 'a brand'} (may be the brand's own)`,
    free_hosting_lure: (d) => `free-hosting address carries a lure word (${d ?? ''})`,
    page_login: () => 'free-hosted page asks for a password or email',
    page_brand_login: (d) => `free-hosted page shows ${d ?? 'a brand'} and asks for login details`,
    page_brand: (d) => `page title names ${d ?? 'a brand'} (no login form)`,
    seed_phrase: () => 'asks for a wallet recovery phrase or private key',
    clickfix: () => 'fake "verify you are human" page telling the visitor to paste a command into Win+R / PowerShell (ClickFix malware lure)',
    lure_message_free_hosting: () => 'message carries a smishing lure and the link is on free hosting',
    geo_divergent: (d) => `a Korean phone and a visitor abroad land on different sites (abroad: ${d ?? ''}) — possible cloaking`,
};
const PHISHING_VERDICT = {
    danger: 'DANGER — strong phishing signs; do not open or enter anything, delete and report (Korea: 118)',
    suspicious: 'SUSPICIOUS — warning signs; do not enter personal or payment details, contact the company through its official app/number',
    unreachable: 'UNREACHABLE — the link no longer resolves (possibly taken down); still do not trust the message',
    official: "OFFICIAL DOMAIN — lands on the company's own domain; still check the sender and the request",
    no_signals: 'NO WARNING SIGNS FOUND — not a guarantee of safety; never enter passwords or card numbers from a text link',
    no_links: 'NO LINKS FOUND in the text',
};
function formatPhishing(data, url) {
    const links = data?.links ?? [];
    const lines = [`=== Phishing Link Check ===`, `Verdict: ${PHISHING_VERDICT[data?.verdict] ?? String(data?.verdict ?? '')}`, ''];
    for (const l of links) {
        lines.push(`[${String(l.verdict).toUpperCase()}] ${l.input}`);
        if (l.finalUrl && l.finalUrl !== l.input)
            lines.push(`  lands on: ${l.finalUrl}${l.hops?.length ? ` (via ${l.hops.length} redirect(s))` : ''}`);
        lines.push(`  domain age: ${l.ageDays == null ? 'unknown' : `${l.ageDays} days`}${l.registrar ? ` · registrar ${l.registrar}` : ''}`);
        for (const s of l.signals ?? []) {
            const f = PHISHING_SIGNAL[s.key];
            lines.push(`  - (${s.severity}) ${f ? f(s.detail) : s.key}`);
        }
    }
    if (data?.lure?.length)
        lines.push('', `Message wording matches common smishing lures: ${data.lure.join(', ')} (a hint, not proof).`);
    lines.push('', 'Scope: observable signals only, checked from DechoNet servers; cloaked pages (shown only to some phones/regions) can look clean. Never call a link "safe" — say "no warning signs found".');
    lines.push(`Full interactive report (share this link with the user): ${url}`);
    return {
        content: [{ type: 'text', text: lines.join('\n') }],
        structuredContent: {
            verdict: String(data?.verdict ?? ''),
            links: links.map((l) => ({ url: String(l.input), finalUrl: String(l.finalUrl ?? ''), verdict: String(l.verdict), ageDays: typeof l.ageDays === 'number' ? l.ageDays : null, signals: (l.signals ?? []).map((s) => String(s.key)) })),
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
        description: "Follow a URL's HTTP redirect chain and audit response security headers (CSP, HSTS, X-Frame-Options, COOP, CORP, COEP, Permissions-Policy), grading A+ to F on the six core headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; COOP/CORP/COEP are reported but not graded) and flagging information leaks such as server-version disclosure. " +
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
                // Areas that can't apply are left out of the score (SYNC: health.ts healthScore).
                const na = new Set();
                if (rdap.status === 'rejected' && rdap.reason?.reason === 'rdap_no_service')
                    na.add('rdap');
                // Extract origin IP for rDNS + ASN
                const aRecord = results.dns?.raw?.records?.find((r) => r.type === 'A');
                if (!aRecord) {
                    na.add('reverseDns');
                    na.add('asn');
                }
                if (aRecord) {
                    const [rdns, asn] = await Promise.allSettled([
                        callApi(`/api/util/reverse-dns?query=${enc(aRecord.value)}`),
                        callApi(`/api/util/asn?query=${enc(aRecord.value)}`),
                    ]);
                    results.reverseDns = get(rdns);
                    results.asn = get(asn);
                }
                // Calculate health score. SYNC: mirrors src/lib/scoring/health.ts (weights,
                // 0.4/0.15 per critical/warning, +0.1 when partial, grade cuts 90/80/70/50/40);
                // tests/unit/mcp-parity.test.ts pins these numbers.
                const weights = { rdap: 10, dns: 18, ssl: 18, http: 14, email: 14, propagation: 8, port: 8, reverseDns: 5, asn: 5 };
                let applicable = 0;
                let lostTotal = 0;
                const areas = [];
                for (const [key, weight] of Object.entries(weights)) {
                    const r = results[key];
                    if (na.has(key)) {
                        areas.push(`${key}: N/A (not scored — ${key === 'rdap' ? 'no RDAP for this TLD' : 'no A record'})`);
                        continue;
                    }
                    applicable += weight;
                    if (!r) {
                        lostTotal += weight;
                        areas.push(`${key}: FAILED (-${weight})`);
                        continue;
                    }
                    const interp = r.interpretation;
                    if (!interp)
                        continue;
                    const criticals = interp.issues?.filter((i) => i.severity === 'critical')?.length || 0;
                    const warnings = interp.issues?.filter((i) => i.severity === 'warning')?.length || 0;
                    let lost = Math.min(weight, Math.round(weight * 0.4 * criticals + weight * 0.15 * warnings));
                    if (interp.partial && lost < weight)
                        lost = Math.min(weight, lost + Math.round(weight * 0.1));
                    lostTotal += lost;
                    const status = lost === 0 ? 'OK' : `ISSUE (-${lost})`;
                    areas.push(`${key}: ${status}`);
                }
                const score = applicable === 0 ? 0 : Math.max(0, Math.min(100, Math.round((100 * (applicable - lostTotal)) / applicable)));
                const grade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : score >= 40 ? 'D' : 'F';
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
            'Unlike security_scan this is PASSIVE (a normal HTTPS request, the TLS certificate and a public CT-log lookup; no port scan, no path probing), so it is suitable for domains you do not own. The sensitive-file check (.env, .git, server-status) runs only for the verified domain owner on the web report (DNS TXT), never through this tool. Use http_security or ssl_check for depth on one layer. ' +
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
        name: 'domain_history',
        title: 'Infrastructure History',
        outputSchema: historyOutputShape,
        annotations: annotate('Infrastructure History'),
        description: 'Show how a domain\'s (or IPv4 address\'s) infrastructure has changed over time from DechoNet\'s stored observations: nameservers, A/AAAA, MX, CNAME, certificate issuer, registrar, RDAP nameservers and status, and for an IP its ASN and PTR — each value with when it was first and last seen. ' +
            'Use this when the question is about the past ("when did the nameservers change?", "which IPs has it used?"); use dns_lookup or rdap_lookup for the current state. Coverage: only what DechoNet itself observed (lookups, watches, own discovery) — not passive DNS. ' +
            'Read-only; requires no API key; rate-limited. Returns per-kind value timelines and a coverage note.',
        schema: {
            target: z.string().describe("Domain (e.g., 'example.com') or IPv4 address. Scheme, path and a leading www. are stripped."),
        },
        handler: async ({ target }) => {
            try {
                return formatHistory(await callApi(`/api/util/history?target=${enc(target)}`));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'infrastructure_pivot',
        title: 'Infrastructure Pivot',
        outputSchema: pivotOutputShape,
        annotations: annotate('Infrastructure Pivot'),
        description: 'Find other domains DechoNet has seen with the same infrastructure value — a nameserver, IP address, MX host, certificate issuer or registrar — with first and last seen, to map related infrastructure (e.g. other phishing domains on the same rare nameserver). ' +
            'Use it after domain_history or dns_lookup gives you a distinctive value. Shared infrastructure (CDN edges, public CAs, large registrars and DNS hosts) returns a count only, since sharing it says nothing about ownership. ' +
            'Read-only; REQUIRES a free DechoNet API key (account page; remote: send Authorization: Bearer dn_…, npm: set DECHONET_API_KEY); 20 rows, 100 with MCP·API Pro; rate-limited. Coverage: only DechoNet\'s own observations.',
        schema: {
            kind: z.enum(['dns:a', 'dns:aaaa', 'dns:ns', 'dns:mx', 'ssl:issuer', 'rdap:registrar', 'rdap:ns']).describe('Which kind of value to pivot on.'),
            value: z.string().describe("The value itself, e.g. 'ns1.example-dns.net' or '203.0.113.9'."),
        },
        handler: async ({ kind, value }) => {
            try {
                return formatPivot(await callApi(`/api/util/pivot?kind=${enc(kind)}&value=${enc(value)}`));
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
            tools: z.array(z.enum(['ssl', 'dns', 'http', 'rdap', 'owasp', 'impersonation', 'pqc', 'exposure'])).optional().describe("Which checks to re-run daily. Default ['ssl','dns','http','rdap'] (certificate, DNS, security headers, registration). Add 'owasp' and/or 'impersonation' for posture and brand-exposure tracking, 'pqc' to record the day post-quantum key exchange is turned on, 'exposure' to catch a newly exposed admin screen, dev tool or staging server."),
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
    {
        name: 'pqc_readiness',
        title: 'Post-Quantum TLS Readiness',
        outputSchema: pqcOutputShape,
        annotations: annotate('Post-Quantum TLS Readiness'),
        description: 'Check whether a website\'s public TLS endpoint is ready for post-quantum cryptography: does it complete a TLS 1.3 handshake that offers only the hybrid X25519MLKEM768 key exchange (ML-KEM), and does the organisation\'s own server provide it or a CDN edge in front of it. Also reports what the certificate chain is signed with (tracked, not scored: public CAs do not issue post-quantum certificates yet). ' +
            'Verdicts: ready (the origin server supports it), partial (a CDN edge provides it; the CDN-to-origin leg is invisible), not_ready (the hybrid-only handshake was refused), unknown (inconclusive; do not report it as "no"). ' +
            'Scope: only the public endpoint on port 443. Internal systems, VPNs, code, and Korean PQC algorithms (no standard TLS codepoints yet) are not observable, so present the result as an external indicator of migration progress, not a full PQC audit. Read-only; requires no API key; rate-limited. Returns the verdict, a 0-100 readiness score and grade, per-check statuses, and a shareable report link.',
        schema: {
            domain: z.string().describe("Domain whose HTTPS endpoint to check (e.g., 'example.com'). Scheme and path are stripped."),
        },
        handler: async ({ domain }) => {
            try {
                return formatPqc(await callApi(`/api/util/pqc?host=${enc(domain)}`), reportUrl('pqc', 'host', domain));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'phishing_link_check',
        title: 'Phishing / Smishing Link Check',
        outputSchema: phishingOutputShape,
        annotations: annotate('Phishing / Smishing Link Check'),
        description: 'Check the links in a suspicious text message (smishing) or e-mail before anyone taps them. Paste the whole message or a single URL: every link is extracted, followed through URL shorteners to its real destination, and judged on observable signals — domain age from RDAP, impersonation of Korean banks/couriers/telecoms/portals and global brands incl. AI services such as ChatGPT/Claude/Gemini (brand keyword, lookalike spelling, or the brand domain worn as a subdomain), ClickFix pages (a fake "verify you are human" check that has the visitor paste a command into Win+R/PowerShell), Android APK downloads, punycode, public phishing/malware feeds, and DechoNet\'s own impersonation tracking. ' +
            'Use this when a user asks whether a link or message is a scam. Verdicts: danger, suspicious, unreachable, official (lands on the brand\'s own domain), no_signals (no warning signs found — never present this as "safe"). ' +
            'Read-only: the first 64 KB of the landing page is read but scripts never run, and the message text is not stored; requires no API key; rate-limited. Returns per-link verdicts with reasons and a shareable report link.',
        schema: {
            text: z.string().describe('The suspicious message exactly as received (any language), or just the URL. Up to 5 links are checked.'),
        },
        handler: async ({ text }) => {
            try {
                const res = await fetch(`${BASE_URL}/api/util/phishing`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'User-Agent': 'DechoNet-MCP/1.0', 'Accept-Language': LOCALE },
                    body: JSON.stringify({ text }),
                });
                const json = await res.json();
                if (!json.ok)
                    throw new Error(json.error?.message || 'API error');
                return formatPhishing(json.data, reportUrl('phishing'));
            }
            catch (e) {
                return errorResult(e.message);
            }
        },
    },
    {
        name: 'exposure_map',
        title: 'Exposed Admin Page Check',
        outputSchema: exposureOutputShape,
        annotations: annotate('Exposed Admin Page Check'),
        description: "Map what an organisation exposes to the internet beyond its home page: subdomains from Certificate Transparency logs (plus hosts DechoNet has already observed), each opened once from outside and sorted into developer/ops tools, directory listings, admin screens, VPN/remote-access logins, staging servers, default install pages, login pages and so on — the forgotten assets AI-driven attack tools look for first. " +
            'Use this when a user wants to know their attack surface or after a breach in their sector. Returns counts per category, a verdict (bad/warn/ok) and what to do. Public view only: the per-host list and a sensitive-file check are shown to the verified domain owner on the web report (DNS TXT), never through this tool. ' +
            'Read-only and passive beyond a single first-page request per host; no logins or path guessing; requires no API key; rate-limited (heavier than other tools — up to ~1 minute).',
        schema: {
            domain: z.string().describe("The organisation's domain (e.g., 'example.co.kr'). Scheme, path and a leading www. are stripped."),
        },
        handler: async ({ domain }) => {
            try {
                return formatExposure(await callApi(`/api/util/exposure?domain=${enc(domain)}`), reportUrl('exposure', 'domain', domain));
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
