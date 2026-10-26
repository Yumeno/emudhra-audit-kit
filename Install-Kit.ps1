#requires -Version 5.1
# ASCII source for Windows PowerShell 5.1.
# Copies the runtime kit from this repository to a working folder outside the repository
# (default: $HOME\emudhra-audit\kit) and records the source commit in KIT_VERSION.txt.
# Audit outputs go to the parent folder ($HOME\emudhra-audit) and never touch the repository.
# Run the audit from the installed kit folder, not from the repository.
# Not safe for concurrent runs against the same destination.
[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $HOME 'emudhra-audit\kit')
)
$ErrorActionPreference = 'Stop'

# Keep in sync with KIT_FILES in install_kit_wsl.sh (Test-Helpers.ps1 checks this in the repository).
$KitFiles = @(
    'emudhra-runbook.md',
    'Test-Emudhra.Helpers.ps1', 'Invoke-Verification.ps1', 'Test-Helpers.ps1',
    'probe_python.py', 'test_probe_python.py', 'TlsProbe.java', 'test_verify_wsl.sh',
    'verify_wsl.sh', 'audit_summary.py', 'install_kit_wsl.sh', 'Replace-GitBrotli.ps1', 'Invoke-CiAudit.ps1'
)
$LfOnlyFiles = @('verify_wsl.sh', 'test_verify_wsl.sh', 'install_kit_wsl.sh', 'probe_python.py', 'test_probe_python.py', 'TlsProbe.java', 'audit_summary.py')
$Marker = 'KIT_VERSION.txt'
$OutputRoot = Join-Path $HOME 'emudhra-audit'

function Get-NormalizedDir([string]$Path) {
    # Resolve against the PowerShell location (not the process CWD); expands '~'. FileSystem only.
    $provider = $null; $drive = $null
    $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    if ($provider.Name -ne 'FileSystem') { throw "Not a file system path: $Path" }
    [IO.Path]::GetFullPath($resolved).TrimEnd('\') + '\'
}

function Get-ExistingAncestors([string]$Dir) {
    # The directory itself (if it exists) and every existing parent up to the root.
    $d = $Dir.TrimEnd('\')
    while ($d) {
        if (Test-Path -LiteralPath $d -PathType Container) { $d }
        $p = Split-Path -Parent $d
        if ($p -eq $d) { break }
        $d = $p
    }
}

function Invoke-GitQuiet([string[]]$Arguments) {
    # Windows PowerShell 5.1 turns redirected native stderr into errors that 'Stop' would throw.
    $previous = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $output = & git @Arguments 2>$null
        [pscustomobject]@{ Code = $LASTEXITCODE; Out = (($output | Out-String).Trim()) }
    } finally { $ErrorActionPreference = $previous }
}

$source = Get-NormalizedDir $PSScriptRoot
$dest = Get-NormalizedDir $Destination
$destPath = $dest.TrimEnd('\')
$parent = Split-Path -Parent $destPath
if (-not $parent) { throw "Destination must not be a drive root: $dest" }

# The kit must live outside the repository (and any git work tree), and must not contain it.
if ($dest.StartsWith($source, [StringComparison]::OrdinalIgnoreCase) -or
    $source.StartsWith($dest, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Destination must be outside the repository (source=$source destination=$dest)."
}
if ($dest -ieq (Get-NormalizedDir $OutputRoot)) { throw "Destination must not be the audit output folder: $dest" }
foreach ($d in @(Get-ExistingAncestors $destPath)) {
    if (Test-Path -LiteralPath (Join-Path $d '.git')) { throw "Destination is inside a git work tree ($d)." }
    # String checks cannot see through junctions/symlinks, so refuse them on the destination path.
    if ((Get-Item -LiteralPath $d -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Destination path contains a junction or symbolic link ($d); use a plain folder."
    }
}
foreach ($name in $KitFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) { throw "Kit file missing in repository: $name" }
}
foreach ($name in $LfOnlyFiles) {
    if ([Array]::IndexOf([IO.File]::ReadAllBytes((Join-Path $source $name)), [byte]13) -ge 0) {
        throw "CRLF found in $name; check .gitattributes / core.autocrlf in the repository."
    }
}
# Replace only an empty folder or a previously installed kit that holds nothing but kit files
# (protects audit outputs that were placed in the folder by mistake).
if (Test-Path -LiteralPath $destPath) {
    if (-not (Test-Path -LiteralPath $destPath -PathType Container)) { throw "Destination exists and is not a folder: $dest" }
    $existing = @(Get-ChildItem -LiteralPath $destPath -Force)
    if ($existing.Count -gt 0) {
        if (-not (Test-Path -LiteralPath (Join-Path $destPath $Marker) -PathType Leaf)) {
            throw "Destination is not empty and has no $Marker file; refusing to overwrite: $dest"
        }
        $allowed = @($KitFiles) + $Marker
        # __pycache__ is created when the kit's Python tests run in place; accept it only when it holds
        # nothing but plain *.pyc files (no links, no subfolders). It is moved away with the old kit.
        $unknown = @($existing | Where-Object {
            if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $true }
            if ($_.PSIsContainer) {
                if ($_.Name -cne '__pycache__') { return $true }
                return @(Get-ChildItem -LiteralPath $_.FullName -Force | Where-Object {
                    $_.PSIsContainer -or ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $_.Extension -ne '.pyc'
                }).Count -gt 0
            }
            $allowed -notcontains $_.Name
        })
        if ($unknown.Count -gt 0) {
            throw "Destination contains non-kit items ($(($unknown | ForEach-Object Name) -join ', ')); move them out first: $dest"
        }
    }
}
$leftovers = @(Get-ChildItem -LiteralPath $parent -Force -Directory -Filter '.kit-old-*' -ErrorAction SilentlyContinue)
if ($leftovers.Count -gt 0) { Write-Warning "Previous kit backups remain (interrupted run?): $(($leftovers | ForEach-Object FullName) -join ', ')" }

# Source version (best effort; 'unknown' when git is unavailable or this is not a repository).
$commit = 'unknown'; $dirty = 'unknown'
if (Get-Command git -ErrorAction SilentlyContinue) {
    $r = Invoke-GitQuiet @('-C', $source, 'rev-parse', 'HEAD')
    if ($r.Code -eq 0 -and $r.Out) {
        $commit = $r.Out
        $s = Invoke-GitQuiet @('-C', $source, 'status', '--porcelain')
        $dirty = if ($s.Code -ne 0) { 'unknown' } elseif ($s.Out) { 'yes' } else { 'no' }
    }
}

# Build in a stage folder, then swap with rollback, so a failure keeps the previous kit.
[void][IO.Directory]::CreateDirectory($parent)
$stage = Join-Path $parent ('.kit-stage-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
try {
    $hashLines = foreach ($name in $KitFiles) {
        $target = Join-Path $stage $name
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination $target
        '{0}  {1}' -f (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant(), $name
    }
    # The sha256 list ends at the first blank line; install_kit_wsl.sh appends its own section after it.
    $info = @(
        "commit=$commit"
        "dirty=$dirty"
        "source=$($source.TrimEnd('\'))"
        "installed_at=$(Get-Date -Format o)"
        "installed_on=$env:COMPUTERNAME"
        ''
        '# sha256'
    ) + $hashLines
    [IO.File]::WriteAllText((Join-Path $stage $Marker), (($info -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))

    $backup = $null
    if (Test-Path -LiteralPath $destPath) {
        $backup = Join-Path $parent ('.kit-old-' + [guid]::NewGuid().ToString('N'))
        Move-Item -LiteralPath $destPath -Destination $backup
    }
    try {
        if (Test-Path -LiteralPath $destPath) { throw "Destination reappeared during install (concurrent run?): $dest" }
        Move-Item -LiteralPath $stage -Destination $destPath
    } catch {
        if ($backup -and -not (Test-Path -LiteralPath $destPath)) { Move-Item -LiteralPath $backup -Destination $destPath }
        throw
    }
    if ($backup) {
        try { Remove-Item -LiteralPath $backup -Recurse -Force }
        catch { Write-Warning "Installed, but could not remove the previous kit backup: $backup" }
    }
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}

"Kit installed: $destPath"
"commit=$commit dirty=$dirty"
if ($dirty -eq 'yes') { Write-Warning 'Repository has uncommitted changes; record this in the report.' }
