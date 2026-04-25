# Vibesecur MCP setup (Cursor + VS Code)

This repo exposes an MCP server at `tools/mcp-server/src/server.js` with tools:

- `health`
- `scanSummary`
- `localScan`
- `scanFile`
- `scanRepo`
- `scanCurrentWorkspace`
- `projectChecklist`
- `buildClaudePrompt`

## Prerequisites

- Node.js installed
- Dependencies installed from repo root:

```powershell
cd O:\vibesecur
npm install
```

## Manual smoke test

```powershell
cd O:\vibesecur
npm run start:mcp
```

The process waits on stdio (no HTTP port). Stop with `Ctrl+C`.

## Cursor MCP config snippet

Use your Cursor MCP servers config and add:

```json
{
  "mcpServers": {
    "vibesecur": {
      "command": "npx",
      "args": ["-y", "@vibesecur/mcp-server"],
      "cwd": "O:\\your-project",
      "env": {}
    }
  }
}
```

Alternative (local clone via npm workspace script):

```json
{
  "mcpServers": {
    "vibesecur": {
      "command": "npm",
      "args": ["run", "start", "-w", "@vibesecur/mcp-server"],
      "cwd": "O:\\vibesecur",
      "env": {}
    }
  }
}
```

## Strict one-folder lock (website download flow)

To lock an MCP install to one folder only:

1. Sign in on the website.
2. Open **MCP** section and generate a locked config using your project folder path.
3. Paste the generated JSON into `~/.cursor/mcp.json`.

Generated locked config includes:

- `VIBESECUR_API_BASE` (required)
- `VIBESECUR_INSTALL_TOKEN` (single-install secret)
- `VIBESECUR_LOCKED_ROOT` (folder binding)
- `VIBESECUR_STRICT_LOCK=true`

With strict lock enabled:

- scans outside `VIBESECUR_LOCKED_ROOT` are blocked locally
- API verifies install token + locked folder hash on every MCP scan
- mismatched repos return `403` with lock error

## VS Code MCP config snippet

In your MCP-capable extension settings (for example Cline/Continue MCP server list), add:

```json
{
  "name": "vibesecur",
  "command": "npx",
  "args": ["-y", "@vibesecur/mcp-server"],
  "cwd": "O:\\your-project",
  "env": {}
}
```

If your extension expects a map/dictionary instead of an array item, keep the same `command`, `args`, and `cwd` values.

## Cursor / VS Code extension (status bar “Vibesecur”)

This repo includes a minimal extension at `tools/vibesecur-cursor-extension/`:

- Adds a status bar button **Vibesecur** that runs the same scan logic as MCP `scanRepo` and prints JSON to **Output → Vibesecur**.
- Command palette: **Vibesecur: Scan Workspace** and **Vibesecur: Copy MCP scanRepo prompt**.

Install in Cursor:

1. `Ctrl+Shift+P` → **Extensions: Install from Folder…**
2. Choose `O:\vibesecur\tools\vibesecur-cursor-extension`
3. Reload the window.

The extension assumes the Vibesecur monorepo stays at `O:\vibesecur` (paths are resolved relative to the extension folder). If you clone elsewhere, reinstall from that clone’s `tools/vibesecur-cursor-extension` folder.

Settings: **Vibesecur: Max Files** (`vibesecur.maxFiles`, default `400`).
