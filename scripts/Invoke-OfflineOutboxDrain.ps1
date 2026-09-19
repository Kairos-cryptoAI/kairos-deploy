[CmdletBinding()]
param(
    [ValidateSet("Inspect", "Apply")]
    [string]$Mode = "Inspect",
    [Parameter(Mandatory = $true)]
    [string]$PlanPath,
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
    [string]$InspectionReceiptPath,
    [string]$InspectionReceiptSignaturePath,
    [string]$AcceptanceReceiptPath,
    [string]$ExpectedInspectionReceiptSha256,
    [switch]$SignInspectionReceipt,
    [switch]$SignAcceptanceReceipt,
    [switch]$ArmApply
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$composeFile = Join-Path $root "docker-compose.outbox-drain.yml"
$validator = Join-Path $root "scripts/validate_offline_outbox_drain.py"
$toolProject = "kairos-offline-outbox-drain-20260920-r1"
$inspectProfile = "offline-outbox-drain-inspect"
$applyProfile = "offline-outbox-drain-apply"
$applyConfirmation = "OFFLINE_OUTBOX_SIGNED_PREFIX_ONLY"
$trustedFingerprint = "40AF365C6682B73D056A6A274DBFF6B65BE9F827"
$allowedProducer = "kairos-quant-scouts"
$allowedTopic = "kairos.market.closed_bar.v1"
$maximumRows = 100
$maximumDurationSeconds = 300

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

function Assert-ExactPlan {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    try {
        $value = Get-Content -Raw -LiteralPath $PathValue | ConvertFrom-Json
    } catch {
        throw "Drain plan is not valid JSON"
    }
    $fields = @($value.PSObject.Properties.Name | Sort-Object)
    if (($fields -join ",") -ne "database_name,drain_id,maximum_duration_seconds,maximum_rows,producer,schema_version,topic") {
        throw "Drain plan must pre-commit exactly its database, scope, ID, row cap, and time cap"
    }
    if ($value.schema_version -ne 1 -or $value.producer -ne $allowedProducer -or $value.topic -ne $allowedTopic) {
        throw "Drain plan producer/topic/schema does not match immutable scope"
    }
    if ([string]::IsNullOrWhiteSpace([string]$value.database_name) -or
        [string]$value.database_name -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,62}$' -or
        [string]::IsNullOrWhiteSpace([string]$value.drain_id) -or
        [string]$value.drain_id.Length -gt 160 -or
        [int]$value.maximum_rows -lt 1 -or [int]$value.maximum_rows -gt $maximumRows -or
        [int]$value.maximum_duration_seconds -lt 30 -or [int]$value.maximum_duration_seconds -gt $maximumDurationSeconds) {
        throw "Drain plan has an invalid bounded database, ID, row cap, or time cap"
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
        [Parameter(Mandatory = $true)][string]$Network,
        [Parameter(Mandatory = $true)][string]$OnlyContainer,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $raw = (& docker network inspect --format '{{json .}}' $Network).Trim()
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

    $services = @(& docker ps --format '{{.Label "com.docker.compose.service"}}' --filter "status=running" --filter "label=com.docker.compose.project=$Project" | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect running scoped Compose services"
    }
    $unexpected = @($services | Where-Object { $_ -notin @("redis", "timescaledb") })
    if ($unexpected.Count -ne 0 -or $services.Count -ne 2) {
        throw "Offline drain requires all producers, consumers, collectors, and execution services to be stopped"
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
        throw "Inspection receipt is not signed by the reviewed offline-drain signer"
    }
}

$inputRoot = Resolve-ExistingDirectory -PathValue $InputDirectory -Label "Explicit operator input directory"
$planFile = Resolve-ExistingFile -PathValue $PlanPath -Label "Signed-prefix drain plan"
if ($planFile -ne (Join-Path $inputRoot "plan.json")) {
    throw "Drain plan must be the explicit input directory's plan.json; it is never inferred"
}
Assert-ExactPlan -PathValue $planFile
$secretRoot = Resolve-ExistingDirectory -PathValue $SecretsDirectory -Label "Scoped drain secrets directory"
[void](Resolve-ExistingFile -PathValue (Join-Path $secretRoot "persistence_database_url") -Label "Scoped PostgreSQL URL file")
if ($Mode -eq "Apply") {
    [void](Resolve-ExistingFile -PathValue (Join-Path $secretRoot "redis_url") -Label "Scoped Redis URL file")
}

if ([string]::IsNullOrWhiteSpace($InspectionReceiptPath)) {
    $InspectionReceiptPath = Join-Path $inputRoot "inspection.json"
}
if ([IO.Path]::GetFullPath($InspectionReceiptPath) -ne [IO.Path]::GetFullPath((Join-Path $inputRoot "inspection.json"))) {
    throw "Inspection receipt must remain in the explicit input directory as inspection.json"
}
if ([string]::IsNullOrWhiteSpace($InspectionReceiptSignaturePath)) {
    $InspectionReceiptSignaturePath = Join-Path $inputRoot "inspection.json.asc"
}
if ([IO.Path]::GetFullPath($InspectionReceiptSignaturePath) -ne [IO.Path]::GetFullPath((Join-Path $inputRoot "inspection.json.asc"))) {
    throw "Inspection receipt signature must remain in the explicit input directory as inspection.json.asc"
}
if ([string]::IsNullOrWhiteSpace($AcceptanceReceiptPath)) {
    $AcceptanceReceiptPath = Join-Path $inputRoot "acceptance.json"
}
if ([IO.Path]::GetFullPath($AcceptanceReceiptPath) -ne [IO.Path]::GetFullPath((Join-Path $inputRoot "acceptance.json"))) {
    throw "Acceptance receipt must remain in the explicit input directory as acceptance.json"
}

Assert-OnlyInfrastructureRunning -Project $ComposeProject
$timescaledb = Assert-ScopedContainer -Service "timescaledb" -Project $ComposeProject
$redis = Assert-ScopedContainer -Service "redis" -Project $ComposeProject
Assert-IsolatedNetwork -Network $DataNetwork -OnlyContainer $timescaledb -Label "PostgreSQL"
Assert-IsolatedNetwork -Network $BusNetwork -OnlyContainer $redis -Label "Redis"

$temporaryEnvironment = Join-Path ([IO.Path]::GetTempPath()) ("kairos-offline-outbox-drain-" + [Guid]::NewGuid().ToString("N") + ".env")
$temporaryCompose = Join-Path ([IO.Path]::GetTempPath()) ("kairos-offline-outbox-drain-" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    [IO.File]::WriteAllText(
        $temporaryEnvironment,
        (@(
            "KAIROS_OFFLINE_OUTBOX_DRAIN_SECRETS_DIR=$secretRoot",
            "KAIROS_OFFLINE_OUTBOX_DRAIN_INPUT_DIR=$inputRoot",
            "KAIROS_OFFLINE_OUTBOX_DRAIN_DATA_NETWORK=$DataNetwork",
            "KAIROS_OFFLINE_OUTBOX_DRAIN_BUS_NETWORK=$BusNetwork"
        ) -join [Environment]::NewLine) + [Environment]::NewLine,
        [Text.UTF8Encoding]::new($false)
    )
    & python $validator
    if ($LASTEXITCODE -ne 0) {
        throw "Offline outbox drain source validation failed"
    }
    $profile = if ($Mode -eq "Inspect") { $inspectProfile } else { $applyProfile }
    & docker compose -p $toolProject --profile $profile --env-file $temporaryEnvironment -f $composeFile config --format json | Set-Content -LiteralPath $temporaryCompose -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "Offline outbox drain profile topology could not be rendered"
    }
    & python $validator --compose-json $temporaryCompose
    if ($LASTEXITCODE -ne 0) {
        throw "Offline outbox drain profile topology validation failed"
    }

    if ($Mode -eq "Inspect") {
        if (Test-Path -LiteralPath $InspectionReceiptPath) {
            throw "Inspection receipt already exists; choose a new explicit input directory"
        }
        $output = @(& docker compose -p $toolProject --profile $inspectProfile --env-file $temporaryEnvironment -f $composeFile run --rm --no-deps --quiet-pull outbox-drain-inspector)
        if ($LASTEXITCODE -ne 0) {
            throw "Read-only bounded-prefix inspection failed"
        }
        $jsonLines = @($output | Where-Object { $_ -match '^\{.*\}$' })
        if ($jsonLines.Count -ne 1) {
            throw "Read-only inspector did not return exactly one redacted receipt"
        }
        $receipt = $jsonLines[0] | ConvertFrom-Json
        if ($receipt.kind -ne "kairos.offline-outbox-drain-inspection.v1" -or $receipt.receipt_sha256 -notmatch '^[0-9a-f]{64}$') {
            throw "Read-only inspector returned a malformed receipt"
        }
        [IO.File]::WriteAllText($InspectionReceiptPath, $jsonLines[0] + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        if ($SignInspectionReceipt) {
            if (Test-Path -LiteralPath $InspectionReceiptSignaturePath) {
                throw "Inspection receipt signature already exists"
            }
            $gpg = Get-GpgProgram
            & $gpg --batch --armor --local-user $trustedFingerprint --detach-sign --output $InspectionReceiptSignaturePath $InspectionReceiptPath
            if ($LASTEXITCODE -ne 0) {
                throw "Could not create a detached inspection receipt signature"
            }
        }
        Write-Output ("Read-only signed-prefix inspection receipt: " + $InspectionReceiptPath)
        exit 0
    }

    if (-not $ArmApply) {
        throw "Apply requires the explicit -ArmApply switch; inspect is the default"
    }
    $receiptFile = Resolve-ExistingFile -PathValue $InspectionReceiptPath -Label "Signed inspection receipt"
    $signatureFile = Resolve-ExistingFile -PathValue $InspectionReceiptSignaturePath -Label "Detached inspection receipt signature"
    if ([string]::IsNullOrWhiteSpace($ExpectedInspectionReceiptSha256) -or $ExpectedInspectionReceiptSha256 -notmatch '^[0-9a-f]{64}$') {
        throw "Apply requires the exact lowercase SHA-256 of the signed inspection receipt"
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $receiptFile).Hash.ToLowerInvariant() -ne $ExpectedInspectionReceiptSha256) {
        throw "Provided inspection receipt SHA-256 does not match the receipt file"
    }
    Test-DetachedReceiptSignature -Receipt $receiptFile -Signature $signatureFile
    if (Test-Path -LiteralPath $AcceptanceReceiptPath) {
        throw "Acceptance receipt already exists; choose a new explicit input directory"
    }
    $result = @(& docker compose -p $toolProject --profile $applyProfile --env-file $temporaryEnvironment -f $composeFile run --rm --no-deps --quiet-pull outbox-drainer --mode apply --plan /run/secrets/offline_outbox_drain_plan --database-url-file /run/secrets/offline_outbox_drain_database_url --redis-url-file /run/secrets/offline_outbox_drain_redis_url --receipt /run/secrets/offline_outbox_drain_receipt --receipt-signature /run/secrets/offline_outbox_drain_receipt_signature --expected-receipt-sha256 $ExpectedInspectionReceiptSha256 --apply-confirmation $applyConfirmation)
    $resultCode = $LASTEXITCODE
    $jsonLines = @($result | Where-Object { $_ -match '^\{.*\}$' })
    if ($jsonLines.Count -ne 1) {
        throw "Bounded drainer did not return exactly one redacted terminal receipt"
    }
    [IO.File]::WriteAllText($AcceptanceReceiptPath, $jsonLines[0] + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    if ($SignAcceptanceReceipt) {
        $acceptanceSignaturePath = Join-Path $inputRoot "acceptance.json.asc"
        if (Test-Path -LiteralPath $acceptanceSignaturePath) {
            throw "Acceptance receipt signature already exists"
        }
        $gpg = Get-GpgProgram
        & $gpg --batch --armor --local-user $trustedFingerprint --detach-sign --output $acceptanceSignaturePath $AcceptanceReceiptPath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create a detached acceptance receipt signature"
        }
    }
    Write-Output $jsonLines[0]
    exit $resultCode
} finally {
    Remove-Item -LiteralPath $temporaryEnvironment -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporaryCompose -Force -ErrorAction SilentlyContinue
}
