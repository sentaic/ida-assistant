<#
.SYNOPSIS
    Start IDA Assistant as a shared streamable-HTTP MCP server.

.DESCRIPTION
    HTTP is bound to 127.0.0.1 and has no authentication. Use it to share one
    scheduler between clients that cannot spawn a stdio process, and never
    expose the port beyond localhost.

.PARAMETER Python
    Python interpreter that has `ida-pro-mcp` installed. Defaults to the
    interpreter managed by `uv tool install ida-pro-mcp`.

.PARAMETER IdaDir
    IDA Professional installation directory.

.PARAMETER ProjectRoot
    Project that owns the managed .ida directory. Must be on a Windows volume.

.PARAMETER Port
    TCP port to bind on 127.0.0.1.
#>
param(
    [string]$Python,
    [string]$IdaDir = $env:IDA_ASSISTANT_IDA_DIR,
    [string]$ProjectRoot = (Get-Location).Path,
    [int]$Port = 8741
)

$ErrorActionPreference = "Stop"

if (-not $Python) {
    $toolDir = (uv tool dir 2>$null)
    if (-not $toolDir) { $toolDir = Join-Path $env:LOCALAPPDATA "uv\tools" }
    $Python = Join-Path $toolDir "ida-pro-mcp\Scripts\python.exe"
}
if (-not (Test-Path $Python)) {
    throw "Python interpreter not found: $Python`nInstall the dependency first: uv tool install ida-pro-mcp"
}

if (-not $IdaDir) { $IdaDir = "C:\Program Files\IDA Professional 9.4" }
if (-not (Test-Path $IdaDir)) {
    throw "IDA directory not found: $IdaDir`nPass -IdaDir or set IDA_ASSISTANT_IDA_DIR."
}

# `ida_pro_mcp` lives in the tool environment, not next to $Python.
$sitePackages = Join-Path (Split-Path -Parent (Split-Path -Parent $Python)) "Lib\site-packages"

$pluginRoot = Split-Path -Parent $PSScriptRoot
& $Python "$pluginRoot\scripts\ida_lazy_mcp.py" `
    --transport streamable-http `
    --host 127.0.0.1 `
    --port $Port `
    --agent shared-http `
    --project-root $ProjectRoot `
    --worker-command $Python `
    --ida-dir $IdaDir `
    --pythonpath $sitePackages `
    --max-sessions 8 `
    --max-workers 3 `
    --worker-idle-seconds 60 `
    --session-idle-seconds 900 `
    --startup-timeout 270 `
    --call-timeout 270 `
    --analysis-timeout 0 `
    --flush-timeout 0 `
    --drain-timeout 900
