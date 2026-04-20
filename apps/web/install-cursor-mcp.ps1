$ErrorActionPreference = "Stop"

param(
  [string]$ProjectPath = (Get-Location).Path
)

$ProjectPath = [System.IO.Path]::GetFullPath($ProjectPath)
$CursorDir = Join-Path $ProjectPath ".cursor"
$McpFile = Join-Path $CursorDir "mcp.json"

if (!(Test-Path $ProjectPath)) {
  throw "Project path does not exist: $ProjectPath"
}

New-Item -ItemType Directory -Force -Path $CursorDir | Out-Null

$apiKey = $env:ANTHROPIC_API_KEY
$envBlock = @{}
if ($apiKey -and $apiKey.Trim().Length -gt 0) {
  $envBlock.ANTHROPIC_API_KEY = $apiKey.Trim()
}

$jsonObj = @{
  mcpServers = @{
    vibesecur = @{
      command = "npx"
      args = @("-y", "@vibesecur/mcp-server")
      env = $envBlock
    }
  }
}

$json = $jsonObj | ConvertTo-Json -Depth 8
Set-Content -Path $McpFile -Value $json -Encoding UTF8

Write-Host ""
Write-Host "Vibesecur MCP configured for this folder only." -ForegroundColor Green
Write-Host "Project: $ProjectPath"
Write-Host "File:    $McpFile"
Write-Host ""
Write-Host "Next step: restart Cursor in this project."
