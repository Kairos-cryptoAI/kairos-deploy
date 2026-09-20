<#
.SYNOPSIS
    Collects redacted evidence for exactly one expired outbox lease on the
    legacy runtime schema 001--012.

.DESCRIPTION
    This tool is inspect-only.  It has no Redis connection, no apply mode, no
    source mutation route, and no trading authority.  An eligible receipt can
    be used only by a later separately reviewed isolated clone rehearsal.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectationPath,
    [Parameter(Mandatory = $true)]
    [string]$InputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$SecretsDirectory,
    [Parameter(Mandatory = $true)]
    [string]$DataNetwork,
    [Parameter(Mandatory = $true)]
    [string]$ComposeProject,
    [Parameter(Mandatory = $true)]
    [string]$BackupManifestPath,
    [string]$ReceiptPath,
    [string]$ReceiptSignaturePath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$composeFile = Join-Path $root "docker-compose.legacy-outbox-inspection.yml"
$validator = Join-Path $root "scripts/validate_legacy_outbox_inspection.py"
$receiptVerifier = Join-Path $root "scripts/verify_legacy_outbox_receipt.py"
$sourceLockFile = Join-Path $root "legacy-outbox-inspection.sources.lock.json"
$packagedSourceLockFile = Join-Path $root "tests/legacy_outbox_inspection/source-lock.json"
$inspectorDockerfile = Join-Path $root "tests/legacy_outbox_inspection/Dockerfile"
$inspectorDockerignore = Join-Path $root "tests/legacy_outbox_inspection/.dockerignore"
$toolProject = "kairos-legacy-outbox-inspection-20260920-r1"
$inspectProfile = "legacy-outbox-inspect"
$trustedFingerprint = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
$expectedSourceProject = "kairos-paper-gate"
$expectedSourceDatabase = "kairos"
# docker-compose.paper.yml names its internal PostgreSQL network `paper-data`.
# Keep this exact project-qualified name as part of the source-identity boundary:
# accepting a generic `*_data` network could attach the inspector to an unrelated
# Compose project that happened to expose PostgreSQL.
$expectedDataNetwork = $expectedSourceProject + "_paper-data"
$maximumBackupAge = [TimeSpan]::FromHours(2)

function Resolve-ExistingFile {
    param([Parameter(Mandatory = $true)][string]$PathValue, [Parameter(Mandatory = $true)][string]$Label)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) { throw "$Label is required" }
    return (Resolve-Path -LiteralPath $PathValue).Path
}

function Resolve-ExistingDirectory {
    param([Parameter(Mandatory = $true)][string]$PathValue, [Parameter(Mandatory = $true)][string]$Label)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Container)) { throw "$Label is required" }
    return (Resolve-Path -LiteralPath $PathValue).Path
}

function Assert-ExactExpectation {
    param([Parameter(Mandatory = $true)][string]$PathValue)
    try { $value = Get-Content -Raw -LiteralPath $PathValue | ConvertFrom-Json }
    catch { throw "Exact legacy row expectation is not valid JSON" }
    $fields = @($value.PSObject.Properties.Name | Sort-Object)
    if (($fields -join ",") -ne "identity,reconciliation_id,schema_version" -or $value.schema_version -ne 1) {
        throw "Expectation must contain exactly schema_version, identity, and reconciliation_id"
    }
    $identity = $value.identity
    $identityFields = @($identity.PSObject.Properties.Name | Sort-Object)
    if (($identityFields -join ",") -ne "id,message_id,payload_sha256,producer,publish_attempts,topic") {
        throw "Expectation must pre-commit every immutable outbox identity field"
    }
    if ([long]$identity.id -le 0 -or [long]$identity.publish_attempts -lt 0 -or
        [string]::IsNullOrWhiteSpace([string]$identity.producer) -or
        [string]::IsNullOrWhiteSpace([string]$identity.message_id) -or
        [string]::IsNullOrWhiteSpace([string]$identity.topic) -or
        [string]$identity.payload_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$value.reconciliation_id)) {
        throw "Expectation has an invalid immutable identity or reconciliation ID"
    }
}

function Assert-ScopedContainer {
    param([Parameter(Mandatory = $true)][string]$Service, [Parameter(Mandatory = $true)][string]$Project)
    $ids = @(& docker ps --quiet --filter "status=running" --filter "label=com.docker.compose.project=$Project" --filter "label=com.docker.compose.service=$Service")
    if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 1 -or $ids[0] -notmatch '^[0-9a-f]{12,64}$') {
        throw "Exactly one running $Service container is required for the supplied Compose project"
    }
    $labelsRaw = (& docker inspect --format '{{json .Config.Labels}}' $ids[0]).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $labelsRaw) { throw "Could not inspect $Service Compose labels" }
    $labels = $labelsRaw | ConvertFrom-Json
    if ($labels.'com.docker.compose.project' -ne $Project -or $labels.'com.docker.compose.service' -ne $Service) {
        throw "Resolved $Service container does not belong to the supplied Compose project"
    }
    return $ids[0]
}

function Assert-OnlyInfrastructureRunning {
    param([Parameter(Mandatory = $true)][string]$Project)
    $ids = @(& docker ps --quiet --filter "status=running" --filter "label=com.docker.compose.project=$Project" | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0 -or @($ids | Where-Object { $_ -notmatch '^[0-9a-f]{12,64}$' }).Count -ne 0) {
        throw "Could not inspect running scoped Compose services"
    }
    $services = foreach ($id in $ids) {
        $labelsRaw = (& docker inspect --format '{{json .Config.Labels}}' $id).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $labelsRaw) { throw "Could not inspect running scoped Compose services" }
        $labels = $labelsRaw | ConvertFrom-Json
        if ($labels.'com.docker.compose.project' -ne $Project -or [string]::IsNullOrWhiteSpace([string]$labels.'com.docker.compose.service')) {
            throw "Could not inspect running scoped Compose services"
        }
        [string]$labels.'com.docker.compose.service'
    }
    $unexpected = @($services | Where-Object { $_ -notin @("redis", "timescaledb") })
    if ($unexpected.Count -ne 0 -or $services.Count -ne 2) {
        throw "Legacy inspection requires all producers, consumers, collectors, and execution services to be stopped"
    }
}

function Assert-IsolatedDataNetwork {
    param([Parameter(Mandatory = $true)][string]$NetworkName, [Parameter(Mandatory = $true)][string]$OnlyContainer)
    $raw = (& docker network inspect --format '{{json .}}' $NetworkName).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $raw) { throw "Could not inspect the supplied PostgreSQL network" }
    $network = $raw | ConvertFrom-Json
    if ($network.Internal -ne $true) { throw "The supplied PostgreSQL network must be Docker-internal" }
    $containers = @($network.Containers.PSObject.Properties.Name)
    if ($containers.Count -ne 1 -or -not $containers[0].StartsWith($OnlyContainer, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The supplied PostgreSQL network must contain only its scoped TimescaleDB container"
    }
}

function Get-GpgProgram {
    $configured = (& git -C $root config --get gpg.program).Trim()
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($configured)) { return $configured }
    return "gpg"
}

function Get-InspectorBuildTag {
    $artifactFiles = @($inspectorDockerfile, (Join-Path $root "tests/legacy_outbox_inspection/runner.py"), $packagedSourceLockFile)
    foreach ($artifact in $artifactFiles) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) { throw "Reviewed legacy inspector build artifact is unavailable" }
    }
    $material = (@($artifactFiles | ForEach-Object { (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash.ToLowerInvariant() }) -join "|")
    $bytes = [Text.Encoding]::UTF8.GetBytes($material)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $digest = -join ($hasher.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) }
    finally { $hasher.Dispose() }
    return "kairos-legacy-outbox-inspector:inspection-" + $digest.Substring(0, 16)
}

function Assert-RenderedInspectorImage {
    param([Parameter(Mandatory = $true)][string]$ComposeJsonPath, [Parameter(Mandatory = $true)][string]$ExpectedImage)
    try { $rendered = Get-Content -Raw -LiteralPath $ComposeJsonPath | ConvertFrom-Json }
    catch { throw "Legacy outbox profile image rendering could not be inspected" }
    if ([string]$rendered.services.'legacy-outbox-inspector'.image -cne $ExpectedImage) {
        throw "Legacy outbox profile image reference differs from the reviewed one-shot build"
    }
}

function Get-SafeInspectionFailure {
    param([Parameter(Mandatory = $true)][object[]]$Output)
    $jsonLines = @($Output | Where-Object { $_ -match '^\{.*\}$' })
    if ($jsonLines.Count -ne 1) { return $null }
    try { $failure = $jsonLines[0] | ConvertFrom-Json } catch { return $null }
    $fields = @($failure.PSObject.Properties.Name | Sort-Object)
    if (($fields -join ",") -ne "classification,error_type,kind,schema_version,state" -or
        $failure.schema_version -ne 1 -or
        $failure.kind -ne "kairos.legacy-outbox-inspection-result.v1" -or
        $failure.classification -ne "LEGACY_RUNTIME_001_012_READ_ONLY" -or
        $failure.state -ne "STARTUP_REJECTED" -or
        [string]$failure.error_type -notmatch '^[A-Za-z0-9_]{1,80}$') { return $null }
    return $failure
}

function Get-VerifiedBackupIdentity {
    param([Parameter(Mandatory = $true)][string]$ManifestPathValue)

    $backupRoot = Resolve-ExistingDirectory -PathValue (Join-Path $root "backups") -Label "Kairos source backup root"
    $manifestFile = Resolve-ExistingFile -PathValue $ManifestPathValue -Label "Verified source backup manifest"
    $manifestDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($manifestFile))
    if (-not [string]::Equals($manifestDirectory, $backupRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Verified source backup manifest must remain in the Kairos backup root"
    }
    try {
        $raw = Get-Content -Raw -LiteralPath $manifestFile
        $manifest = $raw | ConvertFrom-Json
    } catch {
        throw "Verified source backup manifest is not valid JSON"
    }
    $fields = @($manifest.PSObject.Properties.Name | Sort-Object)
    if (($fields -join ",") -ne "bytes,checkpoints,compose_project,created_at_utc,database,file,schema_version,sha256,timescaledb_bgw_owners" -or
        $manifest.schema_version -ne 1 -or
        $manifest.compose_project -ne $expectedSourceProject -or
        $manifest.database -ne $expectedSourceDatabase -or
        [string]$manifest.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [long]$manifest.bytes -le 0 -or
        [string]$manifest.file -notmatch '^kairos-paper-gate-[0-9]{8}T[0-9]{6}Z\.dump$') {
        throw "Verified source backup manifest does not match the required runtime scope"
    }
    $timestampMatch = [regex]::Match($raw, '"created_at_utc"\s*:\s*"(?<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z)"')
    if (-not $timestampMatch.Success) { throw "Verified source backup manifest must contain an explicit UTC timestamp" }
    try { $createdAt = [DateTimeOffset]::Parse($timestampMatch.Groups["timestamp"].Value, [Globalization.CultureInfo]::InvariantCulture) }
    catch { throw "Verified source backup timestamp is invalid" }
    $age = [DateTimeOffset]::UtcNow - $createdAt.ToUniversalTime()
    if ($age -lt [TimeSpan]::Zero -or $age -gt $maximumBackupAge) {
        throw "Verified source backup is not a fresh two-hour runtime verification"
    }
    $dumpPath = [IO.Path]::GetFullPath((Join-Path $backupRoot ([string]$manifest.file)))
    if ([IO.Path]::GetDirectoryName($dumpPath) -ne $backupRoot -or
        -not (Test-Path -LiteralPath $dumpPath -PathType Leaf)) {
        throw "Verified source backup dump is unavailable beside its manifest"
    }
    $dump = Get-Item -LiteralPath $dumpPath
    if ($dump.Length -ne [long]$manifest.bytes -or (Get-FileHash -Algorithm SHA256 -LiteralPath $dumpPath).Hash.ToLowerInvariant() -ne [string]$manifest.sha256) {
        throw "Verified source backup dump does not match its manifest"
    }
    return [pscustomobject]@{
        manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifestFile).Hash.ToLowerInvariant()
        backup_sha256 = [string]$manifest.sha256
        created_at_utc = $timestampMatch.Groups["timestamp"].Value
    }
}

$inputRoot = Resolve-ExistingDirectory -PathValue $InputDirectory -Label "Explicit operator input directory"
$expectationFile = Resolve-ExistingFile -PathValue $ExpectationPath -Label "Exact legacy row expectation"
if ($ComposeProject -cne $expectedSourceProject) {
    throw "Legacy inspection is pinned to the isolated kairos-paper-gate runtime project"
}
if ($DataNetwork -cne $expectedDataNetwork) {
    throw "Legacy inspection is pinned to the isolated kairos-paper-gate_paper-data network"
}
if (-not (Test-Path -LiteralPath $receiptVerifier -PathType Leaf)) { throw "Legacy inspection receipt verifier is unavailable" }
if ($expectationFile -ne (Join-Path $inputRoot "expectation.json")) {
    throw "Expectation must be the explicit input directory's expectation.json; it is never inferred"
}
Assert-ExactExpectation -PathValue $expectationFile
$backup = Get-VerifiedBackupIdentity -ManifestPathValue $BackupManifestPath
$secretRoot = Resolve-ExistingDirectory -PathValue $SecretsDirectory -Label "Scoped legacy inspection secrets directory"
[void](Resolve-ExistingFile -PathValue (Join-Path $secretRoot "persistence_database_url") -Label "Scoped PostgreSQL URL file")
if ([string]::IsNullOrWhiteSpace($ReceiptPath)) { $ReceiptPath = Join-Path $inputRoot "receipt.json" }
if ([IO.Path]::GetFullPath($ReceiptPath) -ne [IO.Path]::GetFullPath((Join-Path $inputRoot "receipt.json"))) {
    throw "Receipt must remain in the explicit input directory as receipt.json"
}
if ([string]::IsNullOrWhiteSpace($ReceiptSignaturePath)) { $ReceiptSignaturePath = Join-Path $inputRoot "receipt.json.asc" }
if ([IO.Path]::GetFullPath($ReceiptSignaturePath) -ne [IO.Path]::GetFullPath((Join-Path $inputRoot "receipt.json.asc"))) {
    throw "Receipt signature must remain in the explicit input directory as receipt.json.asc"
}

Assert-OnlyInfrastructureRunning -Project $ComposeProject
$timescaledb = Assert-ScopedContainer -Service "timescaledb" -Project $ComposeProject
[void](Assert-ScopedContainer -Service "redis" -Project $ComposeProject)
Assert-IsolatedDataNetwork -NetworkName $DataNetwork -OnlyContainer $timescaledb

$temporaryEnvironment = Join-Path ([IO.Path]::GetTempPath()) ("kairos-legacy-outbox-" + [Guid]::NewGuid().ToString("N") + ".env")
$temporaryCompose = Join-Path ([IO.Path]::GetTempPath()) ("kairos-legacy-outbox-" + [Guid]::NewGuid().ToString("N") + ".json")
$temporaryNormalCompose = Join-Path ([IO.Path]::GetTempPath()) ("kairos-legacy-outbox-" + [Guid]::NewGuid().ToString("N") + ".normal.json")
$stagingSuffix = [Guid]::NewGuid().ToString("N")
$stagedReceipt = Join-Path $inputRoot (".legacy-outbox-receipt-" + $stagingSuffix + ".json")
$stagedReceiptSignature = Join-Path $inputRoot (".legacy-outbox-receipt-" + $stagingSuffix + ".json.asc")
$provisionalImage = Get-InspectorBuildTag
try {
    $writeEnvironment = {
        param([Parameter(Mandatory = $true)][string]$ImageReference)
        [IO.File]::WriteAllText($temporaryEnvironment, (@(
            "KAIROS_LEGACY_OUTBOX_SECRETS_DIR=$secretRoot",
            "KAIROS_LEGACY_OUTBOX_INPUT_DIR=$inputRoot",
            "KAIROS_LEGACY_OUTBOX_DATA_NETWORK=$DataNetwork",
            "KAIROS_LEGACY_OUTBOX_BACKUP_MANIFEST_SHA256=$($backup.manifest_sha256)",
            "KAIROS_LEGACY_OUTBOX_BACKUP_SHA256=$($backup.backup_sha256)",
            "KAIROS_LEGACY_OUTBOX_BACKUP_CREATED_AT_UTC=$($backup.created_at_utc)",
            "KAIROS_LEGACY_OUTBOX_IMAGE=$ImageReference"
        ) -join [Environment]::NewLine) + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    }
    & $writeEnvironment $provisionalImage
    & python $validator --source-lock $sourceLockFile --packaged-lock $packagedSourceLockFile --dockerfile $inspectorDockerfile --dockerignore $inspectorDockerignore
    if ($LASTEXITCODE -ne 0) { throw "Legacy outbox source validation failed" }
    & docker compose --project-directory $root -p $toolProject --profile $inspectProfile --env-file $temporaryEnvironment -f $composeFile config --format json | Set-Content -LiteralPath $temporaryCompose -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "Legacy outbox profile topology could not be rendered" }
    Assert-RenderedInspectorImage -ComposeJsonPath $temporaryCompose -ExpectedImage $provisionalImage
    & docker compose --project-directory $root -p $toolProject --env-file $temporaryEnvironment -f $composeFile config --format json | Set-Content -LiteralPath $temporaryNormalCompose -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "Legacy outbox normal-up topology could not be rendered" }
    & python $validator --source-lock $sourceLockFile --packaged-lock $packagedSourceLockFile --dockerfile $inspectorDockerfile --dockerignore $inspectorDockerignore --compose-json $temporaryCompose --normal-up-compose-json $temporaryNormalCompose
    if ($LASTEXITCODE -ne 0) { throw "Legacy outbox profile topology validation failed" }
    if ((Test-Path -LiteralPath $ReceiptPath) -or (Test-Path -LiteralPath $ReceiptSignaturePath)) { throw "Inspection receipt or required signature already exists; choose a new explicit input directory" }
    & docker compose --project-directory $root -p $toolProject --profile $inspectProfile --env-file $temporaryEnvironment -f $composeFile build --pull --no-cache legacy-outbox-inspector
    if ($LASTEXITCODE -ne 0) { throw "Could not build the reviewed legacy read-only inspector image" }
    $imageId = (& docker image inspect --format '{{.Id}}' $provisionalImage).Trim()
    if ($LASTEXITCODE -ne 0 -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') { throw "Fresh legacy inspector image ID is unavailable" }
    & $writeEnvironment $imageId
    & docker compose --project-directory $root -p $toolProject --profile $inspectProfile --env-file $temporaryEnvironment -f $composeFile config --format json | Set-Content -LiteralPath $temporaryCompose -Encoding utf8
    if ($LASTEXITCODE -ne 0) { throw "Immutable legacy inspector profile could not be rendered" }
    Assert-RenderedInspectorImage -ComposeJsonPath $temporaryCompose -ExpectedImage $imageId
    & python $validator --source-lock $sourceLockFile --packaged-lock $packagedSourceLockFile --dockerfile $inspectorDockerfile --dockerignore $inspectorDockerignore --compose-json $temporaryCompose
    if ($LASTEXITCODE -ne 0) { throw "Immutable legacy inspector profile validation failed" }
    # ``docker compose run`` builds only with its explicit --build flag.  The
    # image ID below is the immutable result of the mandatory no-cache build;
    # --pull never prevents a registry substitution before the one-shot run.
    $output = @(& docker compose --project-directory $root -p $toolProject --profile $inspectProfile --env-file $temporaryEnvironment -f $composeFile run --rm --no-deps --pull never legacy-outbox-inspector)
    $inspectionExitCode = $LASTEXITCODE
    $jsonLines = @($output | Where-Object { $_ -match '^\{.*\}$' })
    if ($jsonLines.Count -ne 1) {
        if ($inspectionExitCode -eq 0) { throw "Read-only legacy inspector did not return exactly one redacted receipt" }
        $failure = Get-SafeInspectionFailure -Output $output
        if ($null -eq $failure) { throw "Read-only legacy exact-row inspection failed" }
        throw ("Read-only legacy exact-row inspection rejected: " + $failure.state + " (" + $failure.error_type + ")")
    }
    [IO.File]::WriteAllText($stagedReceipt, $jsonLines[0] + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    & python $receiptVerifier `
        --receipt $stagedReceipt `
        --expectation $expectationFile `
        --backup-manifest-sha256 $backup.manifest_sha256 `
        --backup-sha256 $backup.backup_sha256 `
        --backup-created-at-utc $backup.created_at_utc
    if ($LASTEXITCODE -ne 0) { throw "Read-only legacy inspector returned an invalid or non-redacted receipt" }
    try { $receipt = Get-Content -Raw -LiteralPath $stagedReceipt | ConvertFrom-Json }
    catch { throw "Read-only legacy inspector receipt could not be re-read after verification" }
    $result = [string]$receipt.inspection.result
    if (($result -eq "ELIGIBLE_FOR_CLONE_REHEARSAL" -and $inspectionExitCode -ne 0) -or
        ($result -eq "REJECTED" -and $inspectionExitCode -ne 3)) {
        throw "Read-only legacy inspector returned an unexpected exit status"
    }
    if ($result -eq "REJECTED") {
        Move-Item -LiteralPath $stagedReceipt -Destination $ReceiptPath -ErrorAction Stop
        throw ("Read-only legacy exact-row inspection recorded a rejected receipt: " + $ReceiptPath)
    }
    $gpg = Get-GpgProgram
    & $gpg --batch --armor --local-user $trustedFingerprint --detach-sign --output $stagedReceiptSignature $stagedReceipt
    if ($LASTEXITCODE -ne 0) { throw "Could not create a detached legacy inspection receipt signature" }
    $signatureStatus = @(& $gpg --batch --status-fd 1 --verify $stagedReceiptSignature $stagedReceipt 2>$null)
    if ($LASTEXITCODE -ne 0) { throw "Could not verify the detached legacy inspection receipt signature" }
    $validSignatures = @($signatureStatus | Where-Object { $_ -match '^\[GNUPG:\] VALIDSIG ' })
    $validPrimary = @($validSignatures | Where-Object {
        $parts = @($_.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries))
        $parts.Count -ge 12 -and $parts[11] -ceq $trustedFingerprint
    })
    if ($validSignatures.Count -ne 1 -or $validPrimary.Count -ne 1) {
        throw "Legacy inspection receipt signature does not bind the reviewed signer fingerprint"
    }
    # Publish the signature first: a crash can leave only an unusable orphan
    # signature, never a final eligible receipt without its required proof.
    Move-Item -LiteralPath $stagedReceiptSignature -Destination $ReceiptSignaturePath -ErrorAction Stop
    Move-Item -LiteralPath $stagedReceipt -Destination $ReceiptPath -ErrorAction Stop
    Write-Output ("Read-only legacy 001--012 inspection receipt: " + $ReceiptPath)
} finally {
    Remove-Item -LiteralPath $temporaryEnvironment -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryCompose -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryNormalCompose -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stagedReceipt -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stagedReceiptSignature -Force -ErrorAction SilentlyContinue
}
