<#
.SYNOPSIS
    Resolve this plugin's local paths and write a ready-to-use .mcp.json.

.DESCRIPTION
    Copies .mcp.json.template to .mcp.json with every ${IDA_ASSISTANT_*}
    placeholder replaced by a path on this machine.

    The template is tracked by git; the resolved .mcp.json is gitignored, so
    personal paths never enter history.

.PARAMETER IdaDir
    IDA Professional installation directory. Defaults to IDA_ASSISTANT_IDA_DIR
    or "C:\Program Files\IDA Professional 9.1".

.PARAMETER Force
    Overwrite an existing .mcp.json.
#>
param(
    [string]$IdaDir,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$template = Join-Path $root ".mcp.json.template"
$output = Join-Path $root ".mcp.json"

if (-not (Test-Path $template)) { throw "Template not found: $template" }
if ((Test-Path $output) -and -not $Force) {
    throw "$output already exists. Re-run with -Force to overwrite it."
}

# Locate the Python environment that has ida-pro-mcp installed.
$python = $env:IDA_ASSISTANT_PYTHON
if (-not $python) {
    $toolDir = (uv tool dir 2>$null)
    if (-not $toolDir) { $toolDir = Join-Path $env:LOCALAPPDATA "uv\tools" }
    $python = Join-Path $toolDir "ida-pro-mcp\Scripts\python.exe"
}
if (-not (Test-Path $python)) {
    throw "Python interpreter not found: $python`nInstall the dependency first: uv tool install ida-pro-mcp"
}

$pythonw = Join-Path (Split-Path -Parent $python) "pythonw.exe"
if (-not (Test-Path $pythonw)) { $pythonw = $python }

if (-not $IdaDir) { $IdaDir = $env:IDA_ASSISTANT_IDA_DIR }
if (-not $IdaDir) { $IdaDir = "C:\Program Files\IDA Professional 9.1" }
if (-not (Test-Path $IdaDir)) {
    throw "IDA directory not found: $IdaDir`nPass -IdaDir or set IDA_ASSISTANT_IDA_DIR."
}

# `ida_pro_mcp` lives in the tool environment, not next to the interpreter.
$sitePackages = Join-Path (Split-Path -Parent (Split-Path -Parent $python)) "Lib\site-packages"

$text = Get-Content -Raw -LiteralPath $template
$map = @{
    'IDA_ASSISTANT_ROOT'       = $root
    'IDA_ASSISTANT_PYTHON'     = $python
    'IDA_ASSISTANT_PYTHONW'    = $pythonw
    'IDA_ASSISTANT_IDA_DIR'    = $IdaDir
    'IDA_ASSISTANT_IDA_MCP_PATH' = $sitePackages
}
foreach ($key in $map.Keys) {
    $text = $text.Replace('${' + $key + '}', $map[$key])
}

$unresolved = [regex]::Matches($text, '\$\{[A-Za-z_][A-Za-z0-9_]*\}') |
    ForEach-Object { $_.Value } | Sort-Object -Unique
if ($unresolved) { throw "Unresolved placeholders remain: $($unresolved -join ', ')" }

Set-Content -LiteralPath $output -Value $text -Encoding UTF8
Write-Host "Wrote $output"
Write-Host "  python    : $python"
Write-Host "  ida-dir   : $IdaDir"
Write-Host "  pythonpath: $sitePackages"
