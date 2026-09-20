[CmdletBinding()]
param(
    [ValidateSet("Inspect", "Apply")]
    [string]$Mode = "Inspect",
    [Parameter(Mandatory = $true)]
    [string]$ExpectationPath,
    [Parameter(Mandatory = $true)]
    [string]$InputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$SecretsDirectory,
    [Parameter(Mandatory = $true)]
    [string]$DataNetwork,
    [Parameter(Mandatory = $true)]
    [string]$BusNetwork,
    [Parameter(Mandatory = $true)]
    [string]$ComposeProject,
    [string]$ReceiptPath,
    [string]$ReceiptSignaturePath,
    [string]$ExpectedReceiptSha256,
    [switch]$SignInspectionReceipt,
    [switch]$ArmApply
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$composeFile = Join-Path $root "docker-compose.outbox-reconciliation.yml"
$validator = Join-Path $root "scripts/validate_offline_outbox_reconciliation.py"
$toolProject = "kairos-offline-outbox-reconciliation-20260919-r1"
$inspectProfile = "offline-outbox-inspect"
$applyProfile = "offline-outbox-apply"
$applyConfirmation = "OFFLINE_OUTBOX_EXACT_ROW_ONLY"
$trustedFingerprint = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"

function Resolve-ExistingFile {
    param([Parameter(Mandatory = $true)][string]$PathValue, [Parameter(Mandatory = $true)][string]$Label)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Leaf)) {
        throw "$Label is required"
    }
    return (Resolve-Path -LiteralPath $PathValue).Path
}

function Resolve-ExistingDirectory {
    param([Parameter(Mandatory = $true)][string]$PathValue, [Parameter(Mandatory = $true)][string]$Label)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Container)) {
        throw "$Label is required"
    }
    return (Resolve-Path -LiteralPath $PathValue).Path
}

function Assert-ExactExpectation {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    try {
        $value = Get-Content -Raw -LiteralPath $PathValue | ConvertFrom-Json
    } catch {
        throw "Exact row expectation is not valid JSON"
    }
    $topLevel = @($value.PSObject.Properties.Name | Sort-Object)
    if (($topLevel -join ",") -ne "identity,reconciliation_id,schema_version" -or $value.schema_version -ne 1) {
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
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [Parameter(Mandatory = $true)][string]$Project
    )

    $ids = @(& docker ps --quiet --filter "status=running" --filter "label=com.docker.compose.project=$Project" --filter "label=com.docker.compose.service=$Service")
    if ($LASTEXITCODE -ne 0 -or $ids.Count -ne 1 -or $ids[0] -notmatch '^[0-9a-f]{12,64}$') {
        throw "Exactly one running $Service container is required for the supplied Compose project"
    }
    $labelsRaw = (& docker inspect --format '{{json .Config.Labels}}' $ids[0]).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $labelsRaw) {
        throw "Could not inspect $Service Compose labels"
    }
    $labels = $labelsRaw | ConvertFrom-Json
    if ($labels.'com.docker.compose.project' -ne $Project -or $labels.'com.docker.compose.service' -ne $Service) {
        throw "Resolved $Service container does not belong to the supplied Compose project"
    }
    return $ids[0]
}

function Assert-IsolatedNetwork {
    param(
        [Parameter(Mandatory = $true)][string]$NetworkName,
        [Parameter(Mandatory = $true)][string]$OnlyContainer,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $raw = (& docker network inspect --format '{{json .}}' $NetworkName).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $raw) {
        throw "Could not inspect the supplied $Label network"
    }
    $network = $raw | ConvertFrom-Json
    if ($network.Internal -ne $true) {
        throw "The supplied $Label network must be Docker-internal"
    }
    $containers = @($network.Containers.PSObject.Properties.Name)
    if ($containers.Count -ne 1 -or -not $containers[0].StartsWith($OnlyContainer, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The supplied $Label network must contain only its scoped infrastructure container"
    }
}

function Assert-OnlyInfrastructureRunning {
    param([Parameter(Mandatory = $true)][string]$Project)

    # Do not use Docker's quote-sensitive ``.Label "..."`` Go template here:
    # Windows PowerShell can strip the inner quotes while invoking a native
    # executable.  Enumerate only scoped container IDs, then parse the same
    # JSON label representation used by Assert-ScopedContainer.
    $ids = @(& docker ps --quiet --filter "status=running" --filter "label=com.docker.compose.project=$Project" | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0 -or @($ids | Where-Object { $_ -notmatch '^[0-9a-f]{12,64}$' }).Count -ne 0) {
        throw "Could not inspect running scoped Compose services"
    }
    $services = foreach ($id in $ids) {
        $labelsRaw = (& docker inspect --format '{{json .Config.Labels}}' $id).Trim()
        if ($LASTEXITCODE -ne 0 -or -not $labelsRaw) {
            throw "Could not inspect running scoped Compose services"
        }
        $labels = $labelsRaw | ConvertFrom-Json
        if ($labels.'com.docker.compose.project' -ne $Project -or [string]::IsNullOrWhiteSpace([string]$labels.'com.docker.compose.service')) {
            throw "Could not inspect running scoped Compose services"
        }
        [string]$labels.'com.docker.compose.service'
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect running scoped Compose services"
    }
    $unexpected = @($services | Where-Object { $_ -notin @("redis", "timescaledb") })
    if ($unexpected.Count -ne 0 -or $services.Count -ne 2) {
        throw "Offline reconciliation requires all producers, consumers, collectors, and execution services to be stopped"
    }
}

function Get-GpgProgram {
    $configured = (& git -C $root config --get gpg.program).Trim()
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($configured)) {
        return $configured
    }
    return "gpg"
}

function Test-DetachedReceiptSignature {
    param(
        [Parameter(Mandatory = $true)][string]$Receipt,
        [Parameter(Mandatory = $true)][string]$Signature
    )

    $gpg = Get-GpgProgram
    $status = @(& $gpg --status-fd 1 --verify $Signature $Receipt 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not ($status -match "^\[GNUPG:\] VALIDSIG $trustedFingerprint")) {
        throw "Inspection receipt is not signed by the reviewed offline-reconciliation signer"
    }
}

function Get-SafeInspectionFailure {
    param([Parameter(Mandatory = $true)][object[]]$Output)

    # A failed inspector is allowed to report only the runner's fixed redacted
    # startup envelope.  Do not echo arbitrary container output: it could
    # contain a driver error, a DSN, or a payload fragment.
    $jsonLines = @($Output | Where-Object { $_ -match '^\{.*\}$' })
    if ($jsonLines.Count -ne 1) {
        return $null
    }
    try {
        $failure = $jsonLines[0] | ConvertFrom-Json
    } catch {
        return $null
    }
    $fields = @($failure.PSObject.Properties.Name | Sort-Object)
    if (($fields -join ",") -ne "classification,error_type,kind,schema_version,state" -or
        $failure.schema_version -ne 1 -or
        $failure.kind -ne "kairos.offline-outbox-reconciliation-result.v1" -or
        $failure.classification -ne "OFFLINE_EXACT_ROW_ONLY" -or
        $failure.state -ne "STARTUP_REJECTED" -or
        [string]$failure.error_type -notmatch '^[A-Za-z0-9_]{1,80}$') {
        return $null
    }
    return $failure
}

$inputRoot = Resolve-ExistingDirectory -PathValue $InputDirectory -Label "Explicit operator input directory"
$expectationFile = Resolve-ExistingFile -PathValue $ExpectationPath -Label "Exact row expectation"
if ($expectationFile -ne (Join-Path $inputRoot "expectation.json")) {
    throw "Expectation must be the explicit input directory's expectation.json; it is never inferred"
}
Assert-ExactExpectation -PathValue $expectationFile
$secretRoot = Resolve-ExistingDirectory -PathValue $SecretsDirectory -Label "Scoped reconciliation secrets directory"
$databaseSecret = Resolve-ExistingFile -PathValue (Join-Path $secretRoot "persistence_database_url") -Label "Scoped PostgreSQL URL file"
if ($Mode -eq "Apply") {
    [void](Resolve-ExistingFile -PathValue (Join-Path $secretRoot "redis_url") -Label "Scoped Redis URL file")
}

if ([string]::IsNullOrWhiteSpace($ReceiptPath)) {
    $ReceiptPath = Join-Path $inputRoot "receipt.json"
}
if ([IO.Path]::GetFullPath($ReceiptPath) -ne [IO.Path]::GetFullPath((Join-Path $inputRoot "receipt.json"))) {
    throw "Receipt must remain in the explicit input directory as receipt.json"
}
if ([string]::IsNullOrWhiteSpace($ReceiptSignaturePath)) {
    $ReceiptSignaturePath = Join-Path $inputRoot "receipt.json.asc"
}
if ([IO.Path]::GetFullPath($ReceiptSignaturePath) -ne [IO.Path]::GetFullPath((Join-Path $inputRoot "receipt.json.asc"))) {
    throw "Receipt signature must remain in the explicit input directory as receipt.json.asc"
}

Assert-OnlyInfrastructureRunning -Project $ComposeProject
$timescaledb = Assert-ScopedContainer -Service "timescaledb" -Project $ComposeProject
$redis = Assert-ScopedContainer -Service "redis" -Project $ComposeProject
Assert-IsolatedNetwork -NetworkName $DataNetwork -OnlyContainer $timescaledb -Label "PostgreSQL"
Assert-IsolatedNetwork -NetworkName $BusNetwork -OnlyContainer $redis -Label "Redis"

$temporaryEnvironment = Join-Path ([IO.Path]::GetTempPath()) ("kairos-offline-outbox-" + [Guid]::NewGuid().ToString("N") + ".env")
$temporaryCompose = Join-Path ([IO.Path]::GetTempPath()) ("kairos-offline-outbox-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    [IO.File]::WriteAllText(
        $temporaryEnvironment,
        (@(
            "KAIROS_OFFLINE_OUTBOX_SECRETS_DIR=$secretRoot",
            "KAIROS_OFFLINE_OUTBOX_INPUT_DIR=$inputRoot",
            "KAIROS_OFFLINE_OUTBOX_DATA_NETWORK=$DataNetwork",
            "KAIROS_OFFLINE_OUTBOX_BUS_NETWORK=$BusNetwork"
        ) -join [Environment]::NewLine) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    & python $validator
    if ($LASTEXITCODE -ne 0) {
        throw "Offline outbox profile source validation failed"
    }
    $profile = if ($Mode -eq "Inspect") { $inspectProfile } else { $applyProfile }
    # Validate both explicitly profiled services before running either one. A
    # profile-specific ``config`` projection contains only the inspector and
    # would otherwise make the full fail-closed topology validator reject a
    # healthy inspect-only invocation.
    & docker compose -p $toolProject --profile $inspectProfile --profile $applyProfile --env-file $temporaryEnvironment -f $composeFile config --format json | Set-Content -LiteralPath $temporaryCompose -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "Offline outbox profile topology could not be rendered"
    }
    & python $validator --compose-json $temporaryCompose
    if ($LASTEXITCODE -ne 0) {
        throw "Offline outbox profile topology validation failed"
    }

    if ($Mode -eq "Inspect") {
        if (Test-Path -LiteralPath $ReceiptPath) {
            throw "Inspection receipt already exists; choose a new explicit input directory"
        }
        $output = @(& docker compose -p $toolProject --profile $inspectProfile --env-file $temporaryEnvironment -f $composeFile run --rm --no-deps --quiet-pull outbox-inspector)
        $inspectionExitCode = $LASTEXITCODE
        if ($inspectionExitCode -ne 0) {
            $failure = Get-SafeInspectionFailure -Output $output
            if ($null -eq $failure) {
                throw "Read-only exact-row inspection failed"
            }
            throw ("Read-only exact-row inspection rejected: " + $failure.state + " (" + $failure.error_type + ")")
        }
        $jsonLines = @($output | Where-Object { $_ -match '^\{.*\}$' })
        if ($jsonLines.Count -ne 1) {
            throw "Read-only inspector did not return exactly one redacted receipt"
        }
        $receipt = $jsonLines[0] | ConvertFrom-Json
        if ($receipt.kind -ne "kairos.offline-outbox-inspection.v1" -or $receipt.receipt_sha256 -notmatch '^[0-9a-f]{64}$') {
            throw "Read-only inspector returned a malformed receipt"
        }
        [IO.File]::WriteAllText($ReceiptPath, $jsonLines[0] + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        if ($SignInspectionReceipt) {
            if (Test-Path -LiteralPath $ReceiptSignaturePath) {
                throw "Receipt signature already exists"
            }
            $gpg = Get-GpgProgram
            & $gpg --batch --armor --local-user $trustedFingerprint --detach-sign --output $ReceiptSignaturePath $ReceiptPath
            if ($LASTEXITCODE -ne 0) {
                throw "Could not create a detached inspection receipt signature"
            }
        }
        Write-Output ("Read-only inspection receipt: " + $ReceiptPath)
        exit 0
    }

    if (-not $ArmApply) {
        throw "Apply requires the explicit -ArmApply switch; inspect is the default"
    }
    $receiptFile = Resolve-ExistingFile -PathValue $ReceiptPath -Label "Signed inspection receipt"
    $signatureFile = Resolve-ExistingFile -PathValue $ReceiptSignaturePath -Label "Detached inspection receipt signature"
    if ([string]::IsNullOrWhiteSpace($ExpectedReceiptSha256) -or $ExpectedReceiptSha256 -notmatch '^[0-9a-f]{64}$') {
        throw "Apply requires the exact lowercase SHA-256 of the signed inspection receipt"
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $receiptFile).Hash.ToLowerInvariant() -ne $ExpectedReceiptSha256) {
        throw "Provided receipt SHA-256 does not match the receipt file"
    }
    Test-DetachedReceiptSignature -Receipt $receiptFile -Signature $signatureFile
    $result = @(& docker compose -p $toolProject --profile $applyProfile --env-file $temporaryEnvironment -f $composeFile run --rm --no-deps --quiet-pull outbox-reconciler --mode apply --expectation /run/secrets/offline_outbox_expectation --database-url-file /run/secrets/offline_outbox_database_url --redis-url-file /run/secrets/offline_outbox_redis_url --receipt /run/secrets/offline_outbox_receipt --receipt-signature /run/secrets/offline_outbox_receipt_signature --expected-receipt-sha256 $ExpectedReceiptSha256 --apply-confirmation $applyConfirmation)
    $resultCode = $LASTEXITCODE
    $jsonLines = @($result | Where-Object { $_ -match '^\{.*\}$' })
    if ($jsonLines.Count -ne 1) {
        throw "One-shot reconciler did not return exactly one redacted terminal result"
    }
    Write-Output $jsonLines[0]
    exit $resultCode
} finally {
    Remove-Item -LiteralPath $temporaryEnvironment -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryCompose -Force -ErrorAction SilentlyContinue
}
