// Command-line mode (2026-10-17, free-tool review): the same tools as the MCP server, for a person at a terminal
// or a CI step. `npx dechonet-mcp ssl example.com`. With no arguments the package stays an MCP stdio server.
// Output is the MCP text report without the raw JSON (`--json` prints the structured result instead).
// Exit codes: 0 done, 1 the lookup failed, 2 the result is at least as bad as --fail-on (bad | warn).

process.env.DECHONET_CLIENT = 'cli';

const ALIASES: Record<string, string> = {
  dns: 'dns_lookup', ssl: 'ssl_check', tls: 'ssl_check', http: 'http_security', headers: 'http_security', email: 'email_auth', mail: 'email_auth',
  port: 'port_scan', ports: 'port_scan', propagation: 'dns_propagation', rdns: 'reverse_dns', 'reverse-dns': 'reverse_dns', asn: 'asn_lookup',
  whois: 'whois_lookup', rdap: 'whois_lookup', subdomains: 'subdomain_discovery', lookalike: 'lookalike_domains', scan: 'security_scan', all: 'security_scan',
  owasp: 'owasp_check', golive: 'golive_check', pqc: 'pqc_readiness', mcp: 'mcp_server_check', phishing: 'phishing_link_check', link: 'phishing_link_check',
  exposure: 'exposure_map', changes: 'domain_changes', history: 'domain_history', impersonation: 'impersonation_exposure', ip: 'ip_info', subnet: 'subnet_calc',
};
/** Tools that save something or need an account — not offered on the command line. */
const NOT_CLI = new Set(['watch_domain', 'set_expectations', 'verify_expectations', 'report_page', 'check_before_action', 'email_header_analysis', 'infrastructure_pivot', 'case_kit_search', 'case_kit_observe', 'asm_nuclei_start', 'asm_nuclei_status', 'asm_nuclei_cancel']);

export interface CliArgs { tool: string | null; value: string | null; json: boolean; raw: boolean; failOn: 'bad' | 'warn' | null; port: number | null; help: boolean }

/** Pure: argv (after the script) → what to do. */
export function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = { tool: null, value: null, json: false, raw: false, failOn: null, port: null, help: false };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '--raw') out.raw = true;
    else if (a === '-h' || a === '--help' || a === 'help') out.help = true;
    else if (a.startsWith('--fail-on')) { const v = a.includes('=') ? a.split('=')[1] : argv[++i]; out.failOn = v === 'warn' ? 'warn' : v === 'bad' ? 'bad' : null; }
    else if (a.startsWith('--port')) { const v = a.includes('=') ? a.split('=')[1] : argv[++i]; const n = Number(v); out.port = Number.isInteger(n) && n > 0 && n <= 65535 ? n : null; }
    else rest.push(a);
  }
  if (rest[0]) out.tool = ALIASES[rest[0].toLowerCase()] ?? rest[0].toLowerCase();
  if (rest.length > 1) out.value = rest.slice(1).join(' ');
  return out;
}

/** Pure: whether the result reaches the --fail-on level — its status, or for the all-in-one scan its grade (bad = D/F, warn = C or below). */
export function failsOn(r: { status?: string; verdict?: string; grade?: string } | undefined, failOn: CliArgs['failOn']): boolean {
  if (!failOn || !r) return false;
  const s = (r.status ?? '').toLowerCase();
  if (s) return s === 'bad' || (failOn === 'warn' && s === 'warn');
  const v = (r.verdict ?? '').toLowerCase();
  if (v) return v === 'danger' || (failOn === 'warn' && v === 'suspicious');
  const g = (r.grade ?? '').toUpperCase();
  if (!g) return false;
  return g === 'D' || g === 'F' || (failOn === 'warn' && g === 'C');
}

/** Pure: the human report — the tool's text without the raw JSON block (kept with --raw). */
export function humanText(text: string, raw: boolean): string {
  if (raw) return text;
  const at = text.indexOf('\n---\nRaw data (JSON):');
  if (at < 0) return text;
  const tail = text.slice(at).split('\n').filter((l) => /^(Full report on DechoNet|Signed observation receipt)/.test(l) || /^ {2}\w+: https:\/\/dechonet\.com\/e\//.test(l));
  return [text.slice(0, at).trimEnd(), '', ...tail].join('\n').trimEnd();
}

const HELP = `DechoNet from the command line — the same checks as https://dechonet.com/util, no account needed.

  npx dechonet-mcp <check> <target> [--json] [--raw] [--fail-on bad|warn] [--port N]

Checks: ${Object.keys(ALIASES).join(', ')}
        (or any tool name from the MCP server, e.g. ssl_check)

Examples:
  npx dechonet-mcp ssl example.com
  npx dechonet-mcp email example.com --json
  npx dechonet-mcp scan example.com --fail-on bad      # exit 2 when the overall grade is D or F (CI)

Exit codes: 0 done, 1 the lookup failed, 2 the result reached --fail-on.
Limits and terms: https://dechonet.com/developers · free for non-commercial use.
With no arguments this package runs as an MCP server on stdio.`;

export async function runCli(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.help || !args.tool) { console.log(HELP); return args.help ? 0 : 1; }
  const { tools } = await import('./tools.js');
  const tool = tools.find((t) => t.name === args.tool && !NOT_CLI.has(t.name));
  if (!tool) { console.error(`Unknown check "${argv[0]}". Run with --help for the list.`); return 1; }
  const keys = Object.keys(tool.schema);
  const first = keys.find((k) => k !== 'port' && k !== 'type');
  if (first && !args.value) { console.error(`Usage: npx dechonet-mcp ${argv[0]} <${first}>`); return 1; }
  const input: Record<string, unknown> = first ? { [first]: args.value } : {};
  if (args.port && keys.includes('port')) input.port = args.port;
  else if (keys.includes('port')) input.port = 443;
  const result = await tool.handler(input);
  if (result?.isError) { console.error(result.content?.[0]?.text ?? 'Error'); return 1; }
  if (args.json) console.log(JSON.stringify(result.structuredContent ?? { text: result.content?.map((c: any) => c.text).join('\n') }, null, 2));
  else console.log(humanText(result.content?.map((c: any) => c.text).join('\n') ?? '', args.raw));
  return failsOn(result?.structuredContent, args.failOn) ? 2 : 0;
}
