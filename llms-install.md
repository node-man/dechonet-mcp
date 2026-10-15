# Installing DechoNet MCP (for AI agents such as Cline)

DechoNet needs no API key and no account. Two ways to connect; use the first unless the user asks otherwise.

## Option 1 — npm package (stdio, works in every MCP client)

Requirements: Node.js 18 or newer (`node --version`).

Add this server to the client's MCP settings (for Cline: `cline_mcp_settings.json`, under `mcpServers`):

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

Nothing else to configure. Optional environment variables (leave them out unless the user has them):
- `DECHONET_API_KEY` — a DechoNet API key, for a separate rate-limit bucket.

## Option 2 — hosted server (Streamable HTTP, nothing to install)

If the client supports remote MCP servers over Streamable HTTP, point it at:

```
https://dechonet.com/mcp
```

For Cline this is a remote server entry with that URL and the Streamable HTTP transport.

## Check it works

Ask: "Run a DechoNet security scan of github.com". The `security_scan` tool should return a 0–100 score, a grade and a per-area breakdown. All tools except `watch_domain` are read-only.

Docs for people: https://dechonet.com/mcp
