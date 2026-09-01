<#
.SYNOPSIS
    Evaluates one Dependabot pull request against the central policy and emits a
    machine-readable decision.

.DESCRIPTION
    Deliberately side-effect free: it decides, it does not act. The GitHub
    workflow and the Azure DevOps policy script both call this and then apply the
    result using their own platform's API. Keeping the decision in one place is
    what stops the two platforms drifting apart.

    On GitHub Actions it additionally writes the decision to $GITHUB_OUTPUT so
    later workflow steps can branch on it.

.PARAMETER DependencyNames
    Comma-separated list. Grouped PRs carry several; the riskiest one wins.

.PARAMETER UpdateType
    Either the semver word (patch/minor/major) or the GitHub Actions form
    ('version-update:semver-patch'). Both are accepted.

.PARAMETER PreviousVersion / NewVersion
    Used to derive the update type when -UpdateType is not supplied. This is the
    Azure DevOps path, where no fetch-metadata action exists.

.EXAMPLE
    ./Get-DependabotPrDecision.ps1 -DependencyNames "Serilog" -UpdateType patch `
        -DependencyType direct:production

.EXAMPLE
    ./Get-DependabotPrDecision.ps1 -DependencyNames "Npgsql" `
        -PreviousVersion 8.0.1 -NewVersion 9.0.0 -DependencyType direct:production
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $DependencyNames,

    [string] $UpdateType,
    [string] $PreviousVersion,
    [string] $NewVersion,

    [string] $DependencyType = 'unknown',

    [string] $AlertState,
    [string] $Cvss,
    [string] $GhsaId,

    [string] $ChangedPaths,
    [int]    $ReleaseAgeDays = -1,

    [string] $PolicyPath = (Join-Path $PSScriptRoot '..\config\policy.json'),
    [string] $AuditPath,

    [string] $Platform   = 'GitHub',
    [string] $Repository = '',
    [string] $PullRequestId = ''
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'modules\DependabotPolicy.psm1') -Force

Initialize-DbLogging -Component 'Get-DependabotPrDecision' -AuditPath $AuditPath

$policy = Get-DbPolicy -Path $PolicyPath

# ---------------------------------------------------------------------------
#  Normalise inputs
# ---------------------------------------------------------------------------

$deps = @($DependencyNames -split '\s*,\s*' | Where-Object { $_ })
$paths = @()
if ($ChangedPaths) { $paths = @($ChangedPaths -split '\s*,\s*' | Where-Object { $_ }) }

# GitHub's fetch-metadata emits 'version-update:semver-patch'; Azure DevOps gives
# us nothing and we derive it from the versions in the PR title.
$normalisedUpdateType = 'unknown'
if ($UpdateType) {
    $normalisedUpdateType = switch -Regex ($UpdateType) {
        'semver-major' { 'major'; break }
        'semver-minor' { 'minor'; break }
        'semver-patch' { 'patch'; break }
        '^major$'      { 'major'; break }
        '^minor$'      { 'minor'; break }
        '^patch$'      { 'patch'; break }
        default        { 'unknown' }
    }
}
if ($normalisedUpdateType -eq 'unknown' -and $PreviousVersion -and $NewVersion) {
    $normalisedUpdateType = Get-DbSemverChangeType -FromVersion $PreviousVersion -ToVersion $NewVersion
}

$normalisedDependencyType = switch ($DependencyType) {
    'direct:production'  { 'direct:production' }
    'direct:development' { 'direct:development' }
    'indirect'           { 'indirect' }
    default              { 'unknown' }
}

# A PR is a security update if an advisory is attached and still open.
$isSecurity = $false
if ($GhsaId) { $isSecurity = $true }
if ($AlertState -and $AlertState -match 'open|OPEN|auto_dismissed|fixed') { $isSecurity = $true }
if ($AlertState -eq 'dismissed') { $isSecurity = $false }

$cvssScore = 0.0
if ($Cvss) { [void][double]::TryParse($Cvss, [ref]$cvssScore) }

Write-DbLog -Level Info -Message "Evaluating pull request" -Data @{
    repository     = $Repository
    pullRequestId  = $PullRequestId
    dependencies   = ($deps -join ',')
    updateType     = $normalisedUpdateType
    dependencyType = $normalisedDependencyType
    security       = $isSecurity
    cvss           = $cvssScore
}

# ---------------------------------------------------------------------------
#  Decide
# ---------------------------------------------------------------------------

$decision = Resolve-DbUpdateTier `
    -Policy $policy `
    -DependencyNames $deps `
    -UpdateType $normalisedUpdateType `
    -DependencyType $normalisedDependencyType `
    -IsSecurityUpdate $isSecurity `
    -Cvss $cvssScore `
    -ChangedPaths $paths `
    -ReleaseAgeDays $ReleaseAgeDays

$result = [ordered]@{
    tierId                 = $decision.TierId
    autoMerge              = $decision.AutoMerge
    mergeStrategy          = $decision.MergeStrategy
    requiredHumanApprovals = $decision.RequiredHumanApprovals
    requireCiGreen         = $decision.RequireCiGreen
    labels                 = @($decision.Labels)
    slaHours               = $decision.SlaHours
    blocked                = $decision.Blocked
    reasons                = @($decision.Reasons)
    inputs                 = [ordered]@{
        dependencies   = $deps
        updateType     = $normalisedUpdateType
        dependencyType = $normalisedDependencyType
        isSecurity     = $isSecurity
        cvss           = $cvssScore
        ghsaId         = $GhsaId
    }
}

Write-DbAudit -Action 'pr-decision' -Platform $Platform -Repository $Repository `
    -PullRequestId $PullRequestId -TierId $decision.TierId `
    -Decision $(if ($decision.AutoMerge) { 'auto-merge' } else { 'human-review' }) `
    -Evidence @{
        dependencies = ($deps -join ',')
        updateType   = $normalisedUpdateType
        isSecurity   = $isSecurity
        cvss         = $cvssScore
        reasons      = @($decision.Reasons)
    }

# ---------------------------------------------------------------------------
#  Emit
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Decision --------------------------------------------------------"
Write-Host "  tier             : $($decision.TierId)"
Write-Host "  auto-merge       : $($decision.AutoMerge)"
Write-Host "  approvals needed : $($decision.RequiredHumanApprovals)"
Write-Host "  labels           : $($decision.Labels -join ', ')"
Write-Host "  SLA              : $($decision.SlaHours) h"
Write-Host "  reasons          :"
foreach ($r in $decision.Reasons) { Write-Host "    - $r" }
Write-Host "-----------------------------------------------------------------"

if ($env:GITHUB_OUTPUT) {
    $lines = @(
        "tier-id=$($decision.TierId)"
        "auto-merge=$($decision.AutoMerge.ToString().ToLowerInvariant())"
        "merge-strategy=$($decision.MergeStrategy)"
        "required-approvals=$($decision.RequiredHumanApprovals)"
        "labels=$($decision.Labels -join ',')"
        "sla-hours=$($decision.SlaHours)"
        "reasons=$(($decision.Reasons -join ' | ') -replace '[\r\n]', ' ')"
    )
    Add-Content -Path $env:GITHUB_OUTPUT -Value ($lines -join "`n")
}

if ($env:TF_BUILD) {
    Write-Host "##vso[task.setvariable variable=DependabotTierId]$($decision.TierId)"
    Write-Host "##vso[task.setvariable variable=DependabotAutoMerge]$($decision.AutoMerge.ToString().ToLowerInvariant())"
    Write-Host "##vso[task.setvariable variable=DependabotApprovals]$($decision.RequiredHumanApprovals)"
}

$result | ConvertTo-Json -Depth 10
