[CmdletBinding()]
param(
    [string]$ComposeProject = "kairos",
    [string]$ComposeFile = "docker-compose.yml",
    [string]$EnvFile = ".env",
    [string]$OutputDirectory = "backups",
    [string]$Database = "kairos",
    [string]$DatabaseUser = "kairos"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$composePath = (Resolve-Path -LiteralPath (Join-Path $root $ComposeFile)).Path
$envPath = (Resolve-Path -LiteralPath (Join-Path $root $EnvFile)).Path
$backupRoot = Join-Path $root $OutputDirectory
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$backupRoot = (Resolve-Path -LiteralPath $backupRoot).Path
if (-not $backupRoot.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Backup output must remain inside the deployment repository"
}

$compose = @("compose", "-p", $ComposeProject, "--env-file", $envPath, "-f", $composePath)
$container = (& docker @compose ps -q timescaledb).Trim()
if ($LASTEXITCODE -ne 0 -or $container -notmatch '^[0-9a-f]{64}$') {
    throw "A single running TimescaleDB container is required"
}
$actualProject = (& docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' $container).Trim()
if ($LASTEXITCODE -ne 0 -or $actualProject -ne $ComposeProject) {
    throw "Resolved container does not belong to Compose project $ComposeProject"
}

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$name = "kairos-$stamp.dump"
$containerDump = "/tmp/$name"
$localDump = Join-Path $backupRoot $name
try {
    & docker exec $container pg_dump --format=custom --no-owner --no-privileges --username=$DatabaseUser --dbname=$Database --file=$containerDump
    if ($LASTEXITCODE -ne 0) { throw "pg_dump failed" }
    & docker cp "${container}:$containerDump" $localDump
    if ($LASTEXITCODE -ne 0) { throw "docker cp failed" }
}
finally {
    & docker exec $container rm -f -- $containerDump 2>$null | Out-Null
}

$item = Get-Item -LiteralPath $localDump
$manifest = [ordered]@{
    schema_version = 1
    created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    compose_project = $ComposeProject
    database = $Database
    file = $item.Name
    bytes = $item.Length
    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $item.FullName).Hash.ToLowerInvariant()
}
$manifestPath = "$localDump.json"
$manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8
Write-Output $manifestPath
