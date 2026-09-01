<#
.SYNOPSIS
    Shared policy engine for the Dependabot GitHub / Azure DevOps POC.

.DESCRIPTION
    Everything that must behave identically on both platforms lives here:
    semver classification, risk-tier resolution, deny-list evaluation,
    rate-limit-aware HTTP, structured logging and the audit trail.

    Targets Windows PowerShell 5.1 and PowerShell 7+, because Azure Pipelines
    Windows agents still default to 5.1 and hosted Ubuntu agents run 7.x.

.NOTES
    Import with:  Import-Module "$PSScriptRoot/modules/DependabotPolicy.psm1" -Force
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
#  Structured logging + audit trail
# ---------------------------------------------------------------------------

$script:LogContext = @{
    CorrelationId = [guid]::NewGuid().ToString()
    Component     = 'DependabotPolicy'
    AuditPath     = $null
}

function Initialize-DbLogging {
    <#
    .SYNOPSIS
        Sets the correlation id and audit-trail destination for this run.
    .PARAMETER AuditPath
        JSON Lines file that every decision is appended to. Directory is created
        if missing. Pass a path under $(Build.ArtifactStagingDirectory) in CI so
        the trail is published as a build artifact.
    #>
    [CmdletBinding()]
    param(
        [string] $Component = 'DependabotPolicy',
        [string] $CorrelationId,
        [string] $AuditPath
    )

    if ($CorrelationId) { $script:LogContext.CorrelationId = $CorrelationId }
    $script:LogContext.Component = $Component

    if ($AuditPath) {
        $dir = Split-Path -Parent $AuditPath
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
        }
        $script:LogContext.AuditPath = $AuditPath
    }

    Write-DbLog -Level Info -Message "Logging initialised" -Data @{
        component     = $Component
        correlationId = $script:LogContext.CorrelationId
        auditPath     = $AuditPath
    }
}

function Write-DbTextFile {
    <#
    .SYNOPSIS
        Writes text as UTF-8 WITHOUT a byte order mark.
    .DESCRIPTION
        Windows PowerShell 5.1's Set-Content -Encoding utf8 emits a BOM. A BOM at
        the head of a dependabot.yml makes strict YAML parsers fail on line 1, and
        makes JSON Lines unparseable. Everything this POC writes goes through here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Content,
        [switch] $Append
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    if ($Append) {
        [System.IO.File]::AppendAllText($Path, $Content, $utf8NoBom)
    } else {
        [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
    }
}

function Write-DbLog {
    <#
    .SYNOPSIS
        Emits one structured log line. Uses Azure Pipelines / GitHub Actions
        logging commands when it detects it is running inside one, so warnings
        and errors surface in the run summary rather than being buried.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Debug', 'Info', 'Warn', 'Error')]
        [string] $Level = 'Info',

        [Parameter(Mandatory)]
        [string] $Message,

        [hashtable] $Data = @{}
    )

    $record = [ordered]@{
        timestamp     = (Get-Date).ToUniversalTime().ToString('o')
        level         = $Level
        component     = $script:LogContext.Component
        correlationId = $script:LogContext.CorrelationId
        message       = $Message
        data          = $Data
    }

    $json = ($record | ConvertTo-Json -Depth 10 -Compress)

    # Human-readable line for the console, JSON for the log sink.
    $prefix = "[{0}] {1}" -f $Level.ToUpperInvariant(), $Message

    if ($env:TF_BUILD) {
        switch ($Level) {
            'Warn'  { Write-Host "##vso[task.logissue type=warning]$Message" }
            'Error' { Write-Host "##vso[task.logissue type=error]$Message" }
            default { }
        }
        Write-Host $prefix
    }
    elseif ($env:GITHUB_ACTIONS) {
        switch ($Level) {
            'Warn'  { Write-Host "::warning::$Message" }
            'Error' { Write-Host "::error::$Message" }
            default { Write-Host $prefix }
        }
    }
    else {
        switch ($Level) {
            'Debug' { Write-Verbose $prefix }
            'Warn'  { Write-Warning $Message }
            'Error' { Write-Host $prefix -ForegroundColor Red }
            default { Write-Host $prefix }
        }
    }

    if ($script:LogContext.AuditPath) {
        Write-DbTextFile -Path $script:LogContext.AuditPath -Content ($json + "`n") -Append
    }
}

function Write-DbAudit {
    <#
    .SYNOPSIS
        Appends an immutable decision record to the audit trail.
    .DESCRIPTION
        One record per policy decision. This is the artefact you hand an auditor
        when they ask "who approved this dependency change and on what basis".
        Records are append-only JSON Lines; never rewrite them in place.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Action,
        [Parameter(Mandatory)][string] $Platform,
        [Parameter(Mandatory)][string] $Repository,
        [string]    $PullRequestId,
        [string]    $TierId,
        [string]    $Decision,
        [string]    $Actor = 'dependabot-automation',
        [hashtable] $Evidence = @{}
    )

    $record = [ordered]@{
        timestamp     = (Get-Date).ToUniversalTime().ToString('o')
        kind          = 'audit'
        correlationId = $script:LogContext.CorrelationId
        action        = $Action
        platform      = $Platform
        repository    = $Repository
        pullRequestId = $PullRequestId
        tierId        = $TierId
        decision      = $Decision
        actor         = $Actor
        evidence      = $Evidence
    }

    $json = ($record | ConvertTo-Json -Depth 10 -Compress)

    if ($script:LogContext.AuditPath) {
        Write-DbTextFile -Path $script:LogContext.AuditPath -Content ($json + "`n") -Append
    }
    Write-Host "AUDIT $Action $Repository PR#$PullRequestId -> $Decision (tier=$TierId)"
}

# ---------------------------------------------------------------------------
#  Semantic version handling
# ---------------------------------------------------------------------------

function ConvertTo-DbSemver {
    <#
    .SYNOPSIS
        Parses a version string into a comparable object.
    .DESCRIPTION
        Tolerates the shapes actually seen in the wild:
          1.2.3            SemVer
          1.2.3-preview.4  SemVer with prerelease
          1.2              npm shorthand / NuGet two-part
          1.2.3.4          NuGet four-part revision
          v1.2.3           Go / GitHub Actions tag
        Returns $null when the string is not a version at all (git SHAs, ranges).
    #>
    [CmdletBinding()]
    param([string] $Version)

    if ([string]::IsNullOrWhiteSpace($Version)) { return $null }

    $v = $Version.Trim().TrimStart('v', 'V', '=', '^', '~')

    $m = [regex]::Match(
        $v,
        '^(?<major>\d+)(?:\.(?<minor>\d+))?(?:\.(?<patch>\d+))?(?:\.(?<revision>\d+))?(?:[-+](?<pre>.+))?$'
    )
    if (-not $m.Success) { return $null }

    [pscustomobject]@{
        Major      = [int]$m.Groups['major'].Value
        Minor      = if ($m.Groups['minor'].Success) { [int]$m.Groups['minor'].Value } else { 0 }
        Patch      = if ($m.Groups['patch'].Success) { [int]$m.Groups['patch'].Value } else { 0 }
        Revision   = if ($m.Groups['revision'].Success) { [int]$m.Groups['revision'].Value } else { 0 }
        Prerelease = if ($m.Groups['pre'].Success) { $m.Groups['pre'].Value } else { $null }
        Raw        = $Version
    }
}

function Get-DbSemverChangeType {
    <#
    .SYNOPSIS
        Classifies a version bump as major / minor / patch.
    .OUTPUTS
        'major' | 'minor' | 'patch' | 'unknown'
    .NOTES
        'unknown' is deliberately NOT treated as low risk anywhere downstream.
        If we cannot parse it, a human looks at it.
    #>
    [CmdletBinding()]
    param(
        [string] $FromVersion,
        [string] $ToVersion
    )

    $from = ConvertTo-DbSemver -Version $FromVersion
    $to   = ConvertTo-DbSemver -Version $ToVersion

    if ($null -eq $from -or $null -eq $to) { return 'unknown' }

    if ($to.Major -ne $from.Major) { return 'major' }
    if ($to.Minor -ne $from.Minor) { return 'minor' }
    if ($to.Patch -ne $from.Patch) { return 'patch' }
    if ($to.Revision -ne $from.Revision) { return 'patch' }

    # Same numbers, different prerelease tag (e.g. 1.2.3-rc.1 -> 1.2.3).
    if ($to.Prerelease -ne $from.Prerelease) { return 'patch' }

    return 'unknown'
}

function Test-DbWildcardMatch {
    <#
    .SYNOPSIS
        Case-insensitive wildcard match used for the deny list and ignore rules.
    #>
    [CmdletBinding()]
    param(
        [string]   $Value,
        [string[]] $Patterns
    )

    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }

    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $true }
    }
    return $false
}

# ---------------------------------------------------------------------------
#  Policy evaluation
# ---------------------------------------------------------------------------

function Get-DbPolicy {
    <#
    .SYNOPSIS
        Loads and validates config/policy.json.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-Path $Path)) {
        throw "Policy file not found: $Path"
    }

    $policy = Get-Content -Path $Path -Raw -Encoding utf8 | ConvertFrom-Json

    foreach ($required in @('tiers', 'requiredChecks', 'limits', 'schedule')) {
        if (-not ($policy.PSObject.Properties.Name -contains $required)) {
            throw "Policy file $Path is missing the required '$required' section."
        }
    }
    if ($policy.tiers.Count -eq 0) {
        throw "Policy file $Path defines no tiers."
    }

    Write-DbLog -Level Debug -Message "Policy loaded" -Data @{
        path      = $Path
        tierCount = $policy.tiers.Count
        version   = $policy.version
    }

    return $policy
}

function Get-DbPin {
    <#
    .SYNOPSIS
        Returns the pin entries from the policy, optionally filtered.

    .DESCRIPTION
        A "pin" is a deliberate decision to hold a package at a version despite a
        newer one existing. Two modes:

          soft - the PR is still opened; auto-merge is refused. Visibility kept.
          hard - an 'ignore' entry is rendered into dependabot.yml; no PR at all.

        Hard pins are the dangerous ones, because dependabot.yml 'ignore' entries
        suppress SECURITY update pull requests as well as routine version bumps.
        Dependabot *alerts* are unaffected, which is why the reporting script
        reconciles hard pins against open alerts and fails the run when a pinned
        package has an unfixed vulnerability.

    .PARAMETER Mode
        'soft', 'hard' or 'any' (default).

    .PARAMETER Ecosystem
        Restrict to one package ecosystem, e.g. 'nuget'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [ValidateSet('soft', 'hard', 'any')]
        [string] $Mode = 'any',
        [string] $Ecosystem
    )

    if (-not ($Policy.PSObject.Properties.Name -contains 'pins')) { return @() }
    if (-not ($Policy.pins.PSObject.Properties.Name -contains 'entries')) { return @() }

    $entries = @($Policy.pins.entries)

    if ($Mode -ne 'any') {
        $entries = @($entries | Where-Object {
            $m = if ($_.PSObject.Properties.Name -contains 'mode') { $_.mode } else { 'soft' }
            $m -eq $Mode
        })
    }
    if ($Ecosystem) {
        $entries = @($entries | Where-Object {
            (-not ($_.PSObject.Properties.Name -contains 'ecosystem')) -or $_.ecosystem -eq $Ecosystem
        })
    }

    # Comma operator, not bare `return $entries`: PowerShell unrolls a
    # single-element array on return, which turns .Count into $null at the call
    # site and silently breaks any "how many pins are there" check.
    return ,$entries
}

function Test-DbPinExpiry {
    <#
    .SYNOPSIS
        Finds pins whose reviewBy date has passed.
    .DESCRIPTION
        Pins without an expiry silently become permanent architecture. Every pin
        carries a reviewBy date; this surfaces the ones that are overdue so they
        get re-justified or removed rather than quietly accumulating.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [datetime] $AsOf = (Get-Date)
    )

    $expired = @()
    foreach ($pin in (Get-DbPin -Policy $Policy -Mode 'any')) {

        if (-not ($pin.PSObject.Properties.Name -contains 'reviewBy') -or -not $pin.reviewBy) {
            $expired += [pscustomobject]@{
                DependencyName = $pin.dependencyName
                Ecosystem      = $pin.ecosystem
                Mode           = $pin.mode
                Owner          = $pin.owner
                ReviewBy       = $null
                DaysOverdue    = $null
                Problem        = 'no-review-date'
            }
            continue
        }

        # Must be pre-typed: [datetime]::TryParse cannot bind [ref]$null.
        $due = [datetime]::MinValue
        if (-not [datetime]::TryParse($pin.reviewBy, [ref]$due)) {
            $expired += [pscustomobject]@{
                DependencyName = $pin.dependencyName
                Ecosystem      = $pin.ecosystem
                Mode           = $pin.mode
                Owner          = $pin.owner
                ReviewBy       = $pin.reviewBy
                DaysOverdue    = $null
                Problem        = 'unparseable-review-date'
            }
            continue
        }

        if ($due -lt $AsOf) {
            $expired += [pscustomobject]@{
                DependencyName = $pin.dependencyName
                Ecosystem      = $pin.ecosystem
                Mode           = $pin.mode
                Owner          = $pin.owner
                ReviewBy       = $due.ToString('yyyy-MM-dd')
                DaysOverdue    = [int]($AsOf - $due).TotalDays
                Problem        = 'expired'
            }
        }
    }

    return $expired
}

function Resolve-DbUpdateTier {
    <#
    .SYNOPSIS
        Maps one dependency update onto exactly one policy tier.

    .DESCRIPTION
        Tiers are evaluated highest 'rank' first; the first match wins. After a
        tier is chosen, two overrides can still downgrade the outcome:
          1. the deny list forces human approval,
          2. an unparseable version bump forces human approval.

        Returns a decision object, never $null. When nothing matches, the result
        is a fail-closed "no tier" decision that requires human approval.

    .PARAMETER DependencyNames
        All packages touched by the PR. A grouped PR can carry many; the riskiest
        single dependency determines the outcome for the whole PR.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,

        [Parameter(Mandatory)]
        [string[]] $DependencyNames,

        [ValidateSet('major', 'minor', 'patch', 'unknown')]
        [string] $UpdateType = 'unknown',

        [ValidateSet('direct:production', 'direct:development', 'indirect', 'unknown')]
        [string] $DependencyType = 'unknown',

        [bool]   $IsSecurityUpdate = $false,
        [double] $Cvss = 0.0,
        [string[]] $ChangedPaths = @(),
        [int]    $ReleaseAgeDays = -1
    )

    $reasons = New-Object System.Collections.Generic.List[string]

    # -- 1. pick the highest-ranked matching tier ---------------------------
    $matched = $null
    foreach ($tier in ($Policy.tiers | Sort-Object -Property rank -Descending)) {

        $m = $tier.match

        if ($m.PSObject.Properties.Name -contains 'isSecurityUpdate') {
            if ([bool]$m.isSecurityUpdate -ne $IsSecurityUpdate) { continue }
        }
        if ($m.PSObject.Properties.Name -contains 'minCvss' -and $IsSecurityUpdate) {
            if ($Cvss -lt [double]$m.minCvss) { continue }
        }
        if ($m.PSObject.Properties.Name -contains 'updateTypes') {
            if ($m.updateTypes -notcontains $UpdateType) { continue }
        }
        if ($m.PSObject.Properties.Name -contains 'dependencyTypes') {
            if ($m.dependencyTypes -notcontains $DependencyType) { continue }
        }

        $matched = $tier
        $reasons.Add("Matched tier '$($tier.id)' (rank $($tier.rank)).")
        break
    }

    if ($null -eq $matched) {
        $reasons.Add("No tier matched updateType=$UpdateType dependencyType=$DependencyType security=$IsSecurityUpdate. Failing closed.")
        return [pscustomobject]@{
            TierId                 = 'no-match'
            AutoMerge              = $false
            MergeStrategy          = 'squash'
            RequiredHumanApprovals = 1
            RequireCiGreen         = $true
            Labels                 = @('dependencies', 'needs-review', 'unclassified')
            SlaHours               = 720
            Reasons                = $reasons.ToArray()
            Blocked                = $true
        }
    }

    $autoMerge  = [bool]$matched.action.autoMerge
    $approvals  = [int]$matched.action.requiredHumanApprovals
    $labels     = @($matched.action.labels)

    # -- 1a. global auto-merge kill switch -----------------------------------
    # Checked before every other override so there is exactly one place that can
    # turn automation on, and turning it off cannot be defeated by a tier, a
    # deny-list miss or a parsing quirk. Classification still runs: the labels
    # and the rationale are what make a PR reviewable, and those stay useful
    # whether or not anything merges itself.
    $autoMergeGloballyEnabled = $true
    if ($Policy.PSObject.Properties.Name -contains 'autoMerge') {
        if ($Policy.autoMerge.PSObject.Properties.Name -contains 'enabled') {
            $autoMergeGloballyEnabled = [bool]$Policy.autoMerge.enabled
        }
    }

    if (-not $autoMergeGloballyEnabled) {
        if ($autoMerge) {
            $reasons.Add("Tier '$($matched.id)' allows auto-merge, but auto-merge is disabled globally (policy.autoMerge.enabled = false). A human merges this.")
        }
        $autoMerge = $false
        $approvals = [Math]::Max($approvals, 1)
    }

    # -- 2. unparseable bump => never automatic ------------------------------
    if ($UpdateType -eq 'unknown' -and -not $IsSecurityUpdate) {
        if ($autoMerge) {
            $autoMerge = $false
            $approvals = [Math]::Max($approvals, 1)
            $labels   += 'needs-review'
            $reasons.Add("Version change could not be classified as semver; auto-merge withdrawn.")
        }
    }

    # -- 3. soft pins ---------------------------------------------------------
    # A soft pin lets the PR be created so the team retains visibility of what is
    # available, but never lets it merge without a person. This is the safe
    # default for "we hold this package deliberately".
    foreach ($pin in (Get-DbPin -Policy $Policy -Mode 'soft')) {
        foreach ($dep in $DependencyNames) {
            if (Test-DbWildcardMatch -Value $dep -Patterns @($pin.dependencyName)) {
                if ($autoMerge) {
                    $autoMerge = $false
                    $approvals = [Math]::Max($approvals, 1)
                    $labels   += 'needs-review'
                }
                $labels += 'pinned'
                $reasons.Add("Dependency '$dep' is soft-pinned (owner $($pin.owner), review by $($pin.reviewBy)): $($pin.reason)")
            }
        }
    }

    # -- 4. deny list ---------------------------------------------------------
    if ($Policy.PSObject.Properties.Name -contains 'denyAutoMerge') {

        $deny      = $Policy.denyAutoMerge
        $denyPkgs  = if ($deny.PSObject.Properties.Name -contains 'packages') { @($deny.packages) } else { @() }
        $denyPaths = if ($deny.PSObject.Properties.Name -contains 'paths')    { @($deny.paths) }    else { @() }

        foreach ($dep in $DependencyNames) {
            if (Test-DbWildcardMatch -Value $dep -Patterns $denyPkgs) {
                if ($autoMerge) {
                    $autoMerge = $false
                    $approvals = [Math]::Max($approvals, 1)
                    $labels   += 'needs-review'
                }
                $reasons.Add("Dependency '$dep' is on the auto-merge deny list.")
            }
        }

        foreach ($path in $ChangedPaths) {
            if (Test-DbWildcardMatch -Value $path -Patterns $denyPaths) {
                if ($autoMerge) {
                    $autoMerge = $false
                    $approvals = [Math]::Max($approvals, 1)
                    $labels   += 'needs-review'
                }
                $reasons.Add("Changed path '$path' is on the auto-merge deny list.")
            }
        }
    }

    # -- 5. cooldown ----------------------------------------------------------
    # GitHub enforces this natively via the cooldown: block. Azure DevOps does
    # not, so we enforce it here when the caller supplies a release age.
    if ($ReleaseAgeDays -ge 0 -and -not $IsSecurityUpdate -and
        ($Policy.PSObject.Properties.Name -contains 'cooldown')) {

        $needed = switch ($UpdateType) {
            'major' { [int]$Policy.cooldown.semverMajorDays }
            'minor' { [int]$Policy.cooldown.semverMinorDays }
            'patch' { [int]$Policy.cooldown.semverPatchDays }
            default { [int]$Policy.cooldown.defaultDays }
        }

        if ($ReleaseAgeDays -lt $needed) {
            $autoMerge = $false
            $labels   += 'cooldown'
            $reasons.Add("Release is $ReleaseAgeDays day(s) old; cooldown for '$UpdateType' is $needed day(s). Holding.")
        }
    }

    # The 'auto-merge' label is a claim about what will happen, so it must not
    # survive a downgrade. Leaving it on a blocked PR misleads reviewers into
    # thinking the PR is already handled.
    if (-not $autoMerge) {
        $labels = @($labels | Where-Object { $_ -ne 'auto-merge' })
    }

    [pscustomobject]@{
        TierId                 = $matched.id
        AutoMerge              = $autoMerge
        MergeStrategy          = $matched.action.mergeStrategy
        RequiredHumanApprovals = $approvals
        RequireCiGreen         = [bool]$matched.action.requireCiGreen
        Labels                 = ($labels | Select-Object -Unique)
        SlaHours               = [int]$matched.action.slaHours
        Reasons                = $reasons.ToArray()
        Blocked                = $false
    }
}

function Get-DbPinnedVulnerable {
    <#
    .SYNOPSIS
        Reconciles the version pins against open vulnerability alerts.

    .DESCRIPTION
        This is the control that makes hard pinning safe enough to allow at all.

        A hard pin renders an 'ignore' entry into dependabot.yml, and an ignore
        entry suppresses SECURITY update pull requests as well as routine version
        bumps. What it does NOT suppress is the Dependabot ALERT. So the alert
        exists, nobody gets a pull request, and the CVE sits in production until
        somebody happens to look at the security tab.

        This function is that "somebody". It intersects the two lists and
        classifies each hit:

          CRITICAL - hard pin. No automatic fix is coming. Someone must either
                     lift the pin or patch by hand.
          WARNING  - soft pin. Dependabot should still have opened a security PR;
                     the policy engine merely refuses to auto-merge it. If no PR
                     exists, something else is wrong and needs investigating.

    .PARAMETER Alerts
        Objects with at least Package, Repository, Severity, Cvss, PatchedVersion,
        GhsaId, AgeDays and Url properties.

    .OUTPUTS
        Zero or more finding objects, worst first.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)][AllowEmptyCollection()] $Alerts
    )

    $pins = Get-DbPin -Policy $Policy -Mode 'any'
    $findings = New-Object System.Collections.Generic.List[object]

    foreach ($alert in @($Alerts)) {
        foreach ($pin in $pins) {

            if (-not (Test-DbWildcardMatch -Value $alert.Package -Patterns @($pin.dependencyName))) { continue }

            $mode = if ($pin.PSObject.Properties.Name -contains 'mode') { $pin.mode } else { 'soft' }
            $severity = if ($mode -eq 'hard') { 'CRITICAL' } else { 'WARNING' }

            $action = if ($mode -eq 'hard') {
                "Dependabot will NOT open a security PR while this pin stands. Lift the pin, or patch to $($alert.PatchedVersion) by hand."
            } else {
                "A security PR should exist for this. If none has appeared, check the updater logs and the ignore rules."
            }

            $findings.Add([pscustomobject]@{
                Severity       = $severity
                Repository     = $alert.Repository
                Package        = $alert.Package
                PinMode        = $mode
                PinPattern     = $pin.dependencyName
                HoldAt         = $(if ($pin.PSObject.Properties.Name -contains 'holdAt') { $pin.holdAt } else { $null })
                Owner          = $pin.owner
                ReviewBy       = $pin.reviewBy
                AlertSeverity  = $alert.Severity
                Cvss           = $alert.Cvss
                GhsaId         = $alert.GhsaId
                PatchedVersion = $alert.PatchedVersion
                AlertAgeDays   = $alert.AgeDays
                Reason         = $pin.reason
                Url            = $alert.Url
                Action         = $action
            })
        }
    }

    # Worst first: hard pins before soft, then by CVSS.
    $sorted = @($findings | Sort-Object `
        @{ Expression = { if ($_.Severity -eq 'CRITICAL') { 0 } else { 1 } } }, `
        @{ Expression = 'Cvss'; Descending = $true })

    return ,$sorted
}

# ---------------------------------------------------------------------------
#  Metadata recovery (Azure DevOps)
# ---------------------------------------------------------------------------

function Get-DbPrMetadataFromNaming {
    <#
    .SYNOPSIS
        Recovers dependency metadata from a Dependabot branch name and PR title.

    .DESCRIPTION
        GitHub gives you this for free via dependabot/fetch-metadata. Azure DevOps
        gives you a pull request and nothing else, so we reconstruct it.

        Dependabot branch names are deterministic:
            dependabot/nuget/Serilog-3.1.1
            dependabot/npm_and_yarn/src/lodash-4.17.21
            dependabot/nuget/src/Api/Newtonsoft.Json-13.0.3
            dependabot/npm_and_yarn/dev-dependencies-a1b2c3d4e5   (grouped)
            dependabot/github_actions/actions/checkout-4.2.0

        Titles carry the previous version, which the branch name does not:
            "Bump Serilog from 3.0.1 to 3.1.1"
            "chore(deps): bump Serilog from 3.0.1 to 3.1.1"
            "Bump the dev-dependencies group with 3 updates"

    .OUTPUTS
        An object with DependencyNames / PreviousVersion / NewVersion / Ecosystem /
        IsGroup / Source, or $null when nothing usable could be recovered. Callers
        must treat $null as "needs a human", never as "safe to merge".
    #>
    [CmdletBinding()]
    param(
        [string] $SourceBranch,
        [string] $Title
    )

    $branch  = ($SourceBranch -replace '^refs/heads/', '')
    $names   = New-Object System.Collections.Generic.List[string]
    $prev    = $null
    $new     = $null
    $eco     = $null
    $isGroup = $false

    if ($branch -match '^dependabot/(?<eco>[^/]+)/(?<rest>.+)$') {
        $eco  = $Matches['eco']
        $rest = $Matches['rest']

        # Grouped-update branches end in a content hash rather than a version.
        # Distinguishing them matters: a group PR carries many dependencies, and
        # treating the group name as a package name would defeat the deny list.
        if ($rest -match '-[0-9a-f]{8,}$') {
            $isGroup = $true
        }
        elseif ($rest -match '^(?:.*/)?(?<pkg>.+?)-(?<ver>\d[\w\.\-\+]*)$') {
            $names.Add($Matches['pkg'])
            $new = $Matches['ver']
        }
    }

    # The title is the AUTHORITATIVE source for the package name and the only
    # source for the previous version. It wins over the branch-derived name,
    # because the branch form is ambiguous when the package name itself contains
    # a slash: 'dependabot/github_actions/actions/checkout-4.2.0' is
    # package 'actions/checkout', not directory 'actions' + package 'checkout',
    # and nothing in the branch string distinguishes the two cases.
    if ($Title -match '(?i)\bbump\s+(?<pkg>[^\s]+)\s+from\s+(?<from>[^\s]+)\s+to\s+(?<to>[^\s]+)') {
        $titlePkg = $Matches['pkg'].Trim('`', '"', "'")
        $names.Clear()
        $names.Add($titlePkg)
        $prev = $Matches['from']
        $new  = $Matches['to']
    }

    if ($isGroup -and $Title -match '(?i)bump the (?<grp>[^\s]+) group') {
        $names.Add("group:$($Matches['grp'])")
    }

    if ($names.Count -eq 0) { return $null }

    [pscustomobject]@{
        DependencyNames = @($names | Select-Object -Unique)
        PreviousVersion = $prev
        NewVersion      = $new
        Ecosystem       = $eco
        IsGroup         = $isGroup
        Source          = 'branch+title'
    }
}

function Get-DbPrDependencyType {
    <#
    .SYNOPSIS
        Infers direct:production vs direct:development from the changed file paths.

    .DESCRIPTION
        Azure DevOps does not expose dependency type, so it is inferred. The
        inference deliberately errs toward 'production': misclassifying a
        production dependency as development would auto-merge something that
        should have been reviewed, while the reverse only asks for a review that
        was not strictly needed. Only when EVERY changed manifest looks like test
        or benchmark tooling is the update called a development dependency.
    #>
    [CmdletBinding()]
    param([string[]] $ChangedPaths)

    if (-not $ChangedPaths -or $ChangedPaths.Count -eq 0) { return 'unknown' }

    $devIndicators = @(
        '*test*', '*Test*', '*spec*', '*Spec*',
        '*.Tests.csproj', '*.Test.csproj', '*.IntegrationTests.csproj',
        '*benchmark*', '*Benchmark*', '*e2e*'
    )

    foreach ($p in $ChangedPaths) {
        $leaf = Split-Path $p -Leaf
        $isDev = (Test-DbWildcardMatch -Value $leaf -Patterns $devIndicators) -or
                 (Test-DbWildcardMatch -Value $p    -Patterns $devIndicators)
        if (-not $isDev) { return 'direct:production' }
    }

    return 'direct:development'
}

# ---------------------------------------------------------------------------
#  Rate-limit aware HTTP
# ---------------------------------------------------------------------------

function Invoke-DbRestMethod {
    <#
    .SYNOPSIS
        HTTP wrapper with retry, exponential backoff and rate-limit awareness.

    .DESCRIPTION
        Handles the three failure modes that actually bite in this integration:
          * GitHub secondary rate limits  -> honours Retry-After
          * GitHub primary rate limits    -> honours X-RateLimit-Reset
          * Azure DevOps 429 throttling   -> honours Retry-After
        Everything else gets bounded exponential backoff with jitter.

        Uses Invoke-WebRequest rather than Invoke-RestMethod so response headers
        are readable on Windows PowerShell 5.1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Uri,
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]    $Method = 'GET',
        [hashtable] $Headers = @{},
        $Body,
        [string] $ContentType = 'application/json',
        [int]    $MaxAttempts = 5,
        [int]    $BaseDelaySeconds = 2,
        [switch] $AllowNotFound
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{
                Uri             = $Uri
                Method          = $Method
                Headers         = $Headers
                UseBasicParsing = $true
                ErrorAction     = 'Stop'
            }
            if ($null -ne $Body) {
                $params['Body']        = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 20 }
                $params['ContentType'] = $ContentType
            }

            $response = Invoke-WebRequest @params

            # Proactively back off before we hit the wall.
            $remainingHeader = $response.Headers['X-RateLimit-Remaining']
            if ($remainingHeader) {
                $remaining = [int]($remainingHeader | Select-Object -First 1)
                if ($remaining -le 5) {
                    $resetHeader = $response.Headers['X-RateLimit-Reset']
                    if ($resetHeader) {
                        $resetEpoch = [long]($resetHeader | Select-Object -First 1)
                        $resetAt    = [DateTimeOffset]::FromUnixTimeSeconds($resetEpoch).UtcDateTime
                        $waitSec    = [Math]::Max(0, [int]($resetAt - (Get-Date).ToUniversalTime()).TotalSeconds) + 2
                        if ($waitSec -gt 0 -and $waitSec -lt 3900) {
                            Write-DbLog -Level Warn -Message "Approaching API rate limit; sleeping $waitSec s" -Data @{
                                uri = $Uri; remaining = $remaining; resetAtUtc = $resetAt.ToString('o')
                            }
                            Start-Sleep -Seconds $waitSec
                        }
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($response.Content)) { return $null }
            return ($response.Content | ConvertFrom-Json)
        }
        catch {
            $status = $null
            $retryAfter = $null
            if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
                try { $status = [int]$_.Exception.Response.StatusCode } catch { }
                try { $retryAfter = $_.Exception.Response.Headers['Retry-After'] } catch { }
            }

            if ($status -eq 404 -and $AllowNotFound) {
                Write-DbLog -Level Debug -Message "404 (tolerated)" -Data @{ uri = $Uri }
                return $null
            }

            # Do not burn retries on requests that will never succeed.
            # 403 is deliberately excluded: GitHub returns it for secondary rate
            # limits, which retrying does fix.
            if ($status -eq 400 -or $status -eq 401 -or $status -eq 422) {
                Write-DbLog -Level Error -Message "Non-retryable HTTP $status" -Data @{ uri = $Uri; method = $Method }
                throw
            }

            if ($attempt -ge $MaxAttempts) {
                Write-DbLog -Level Error -Message "HTTP call failed after $attempt attempt(s)" -Data @{
                    uri = $Uri; method = $Method; status = $status; error = $_.Exception.Message
                }
                throw
            }

            $delay = if ($retryAfter) {
                [int]$retryAfter
            } else {
                # Exponential backoff with jitter so parallel repo jobs do not
                # synchronise their retries into a thundering herd.
                [int]([Math]::Pow(2, $attempt) * $BaseDelaySeconds) + (Get-Random -Minimum 0 -Maximum 5)
            }

            Write-DbLog -Level Warn -Message "HTTP $status - retry $attempt/$MaxAttempts in ${delay}s" -Data @{
                uri = $Uri; method = $Method
            }
            Start-Sleep -Seconds $delay
        }
    }
}

function New-DbGitHubHeader {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Token)
    @{
        'Authorization'        = "Bearer $Token"
        'Accept'               = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent'           = 'dependabot-poc'
    }
}

function New-DbAzureDevOpsHeader {
    <#
    .SYNOPSIS
        Basic auth header for the Azure DevOps REST API.
    .NOTES
        Azure DevOps expects an empty username and the PAT as the password,
        base64 encoded. $(System.AccessToken) works the same way.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $PersonalAccessToken)

    $pair  = ":$PersonalAccessToken"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
    @{
        'Authorization' = "Basic " + [Convert]::ToBase64String($bytes)
        'Accept'        = 'application/json'
        'User-Agent'    = 'dependabot-poc'
    }
}

Export-ModuleMember -Function @(
    'Initialize-DbLogging'
    'Write-DbTextFile'
    'Write-DbLog'
    'Write-DbAudit'
    'ConvertTo-DbSemver'
    'Get-DbSemverChangeType'
    'Test-DbWildcardMatch'
    'Get-DbPolicy'
    'Get-DbPin'
    'Test-DbPinExpiry'
    'Get-DbPinnedVulnerable'
    'Resolve-DbUpdateTier'
    'Get-DbPrMetadataFromNaming'
    'Get-DbPrDependencyType'
    'Invoke-DbRestMethod'
    'New-DbGitHubHeader'
    'New-DbAzureDevOpsHeader'
)
