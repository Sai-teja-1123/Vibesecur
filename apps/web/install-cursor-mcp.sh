#!/usr/bin/env bash
set -euo pipefail

PROJECT_PATH="${1:-$PWD}"
PROJECT_PATH="$(cd "$PROJECT_PATH" && pwd)"
CURSOR_DIR="$PROJECT_PATH/.cursor"
MCP_FILE="$CURSOR_DIR/mcp.json"

mkdir -p "$CURSOR_DIR"

API_KEY="${ANTHROPIC_API_KEY:-}"

if [[ -n "$API_KEY" ]]; then
  cat > "$MCP_FILE" <<EOF
{
  "mcpServers": {
    "vibesecur": {
      "command": "npx",
      "args": ["-y", "@vibesecur/mcp-server"],
      "env": {
        "ANTHROPIC_API_KEY": "$API_KEY"
      }
    }
  }
}
EOF
else
  cat > "$MCP_FILE" <<'EOF'
{
  "mcpServers": {
    "vibesecur": {
      "command": "npx",
      "args": ["-y", "@vibesecur/mcp-server"],
      "env": {}
    }
  }
}
EOF
fi

echo ""
echo "Vibesecur MCP configured for this folder only."
echo "Project: $PROJECT_PATH"
echo "File:    $MCP_FILE"
echo ""
echo "Next step: restart Cursor in this project."
