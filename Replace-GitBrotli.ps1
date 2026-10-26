# Git for Windows / PortableGit: replace Brotli DLLs older than 1.2.1 with MSYS2 brotli-1.2.1-1 (CVE-2026-111497 mitigation).
# Run in an ELEVATED Windows PowerShell (not Git Bash). Close Git Bash / git GUIs / tools using this Git first.
#   .\Replace-GitBrotli.ps1                                           (C:\Program Files\Git)
#   .\Replace-GitBrotli.ps1 -GitRoot 'D:\Tools\SomeApp\PortableGit'
#   add -Check to only report what would be replaced (needs no elevation)
# Handles both layouts: mingw64 (Git 2.55 and older, PortableGit) and ucrt64 (Git 2.56+).
# MinGit (no bin\curl.exe) works too: the layout is found by bin\libbrotlidec.dll, the shipped version by that DLL's known SHA256,
# and the result is verified by DLL hashes instead of curl -V. A 32-bit Git (mingw32 only) is refused.
# Elevated runs are only for a Git under Program Files that only admins can change. A Git in your own folders: normal PowerShell.
# Replaces the copies in <prefix>\bin AND <prefix>\libexec\git-core (git-remote-https.exe loads the DLLs next to itself).
# Safe to run again after a Git update: a folder that already has 1.2.1 is left alone, a Git that ships 1.2.1 or newer
# is left alone, and each run keeps its own backup of the DLLs it replaced.
# The new DLLs come from <kit output>\brotli-1.2.1-msys2[-ucrt64]. Only when a replacement is needed (never with -Check) and that
# folder is missing or incomplete, the MSYS2 package is
# downloaded (Windows curl.exe), checked against the SHA256 below (the value MSYS2's repository database lists for it) and only its
# three DLLs are taken out with Windows tar.exe; nothing from the package is run. Every DLL is checked against its own SHA256 too.
param([string]$GitRoot = 'C:\Program Files\Git', [switch]$Check, [string]$LogFile = "$env:USERPROFILE\emudhra-audit\changes.log")
$ErrorActionPreference = 'Stop'
$GitRoot = [IO.Path]::GetFullPath($GitRoot).TrimEnd('\')
$names = 'libbrotlicommon.dll','libbrotlidec.dll','libbrotlienc.dll'
$sets = @{
  'mingw64' = @{ pkg = 'mingw-w64-x86_64-brotli-1.2.1-1'; dir = "$env:USERPROFILE\emudhra-audit\brotli-1.2.1-msys2"
                 pkgHash = '3163fae24021624b49d3372a6a7fe05c0f3e01b301e65fcbcb3a95557019fb2d'
                 hash = @{ 'libbrotlicommon.dll'='121006fe45e8bd12b1929f86e1efb1dbd1c6291118f9a409693ce8c030f1cefb'
                           'libbrotlidec.dll'   ='dab7d47981ee887865d1f82dcbcc8fc4c7a43942278bb27877e168909e10d346'
                           'libbrotlienc.dll'   ='07a33fd6cf281dc6dea6606700ede061b8dc7c2b6786f1cd4ab64e7bcbacef22' } }
  'ucrt64'  = @{ pkg = 'mingw-w64-ucrt-x86_64-brotli-1.2.1-1'; dir = "$env:USERPROFILE\emudhra-audit\brotli-1.2.1-msys2-ucrt64"
                 pkgHash = 'e3257d4303fc0aca4c64f702d4c8cd766a321351c5e61927631c30bfdf2e7536'
                 hash = @{ 'libbrotlicommon.dll'='7b0047dc16dd92a7932124dfd5a6e698d342f533a15d37d61f710def66091436'
                           'libbrotlidec.dll'   ='c4c987a01597ddf969d93023f933f999a20f285588b0decb4deeb780c9e9cdf8'
                           'libbrotlienc.dll'   ='03f9a82d293caf5b4065a9641dd5309e27aefc5c8111eeec25f906e47ec6c934' } }
}
function Get-Sha256([byte[]]$b) { $s = [Security.Cryptography.SHA256]::Create(); try { -join ($s.ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) } finally { $s.Dispose() } }
function Get-SetHashes([string]$dir) { $h = @{}; foreach ($n in $names) { $h[$n] = (Get-FileHash -LiteralPath "$dir\$n").Hash.ToLower() }; $h }
function Test-SameSet($a, $b) { foreach ($n in $names) { if ($a[$n] -ne $b[$n]) { return $false } }; $true }
function Get-CurlBrotli([string]$curl) {
  $ErrorActionPreference = 'Continue'   # Git 2.56 curl prints a Debug-enabled warning on stderr; 5.1 would make it fatal
  $line = & $curl -V 2>$null | Where-Object { $_ -match '^curl ' } | Select-Object -First 1
  $m = [regex]::Match("$line", ' brotli/(\d+\.\d+\.\d+)')
  if (-not $m.Success) { throw "curl -V shows no brotli version: $line" }
  $m.Groups[1].Value
}

# libbrotlidec.dll of the brotli 1.2.0 that Git for Windows / PortableGit ship. Used to tell the shipped version when
# bin\curl.exe is absent (MinGit); any other build is not guessed.
$shippedDec = @{
  'mingw64' = @{ 'a142dc6cfa77cb907028aa9426f486f3d8de37855e8db2ae2894147908121881' = '1.2.0' }
  'ucrt64'  = @{ 'e270b6e576594ee8ee6e33ccc54e34a54304616dd6225652e11e49d6f17ef896' = '1.2.0' }
}
# The layout is found by bin\libbrotlidec.dll, not bin\curl.exe (MinGit has no curl.exe).
function Resolve-GitBrotliPrefix([string]$Root) {
  $found = @('mingw64','ucrt64') | Where-Object { Test-Path -LiteralPath "$Root\$_\bin\libbrotlidec.dll" }
  if (@($found).Count -eq 1) { return @($found)[0] }
  if (@($found).Count -gt 1) { throw "both mingw64 and ucrt64 have bin\libbrotlidec.dll under $Root; check by hand" }
  if (Test-Path -LiteralPath "$Root\mingw32\bin\libbrotlidec.dll") { throw "only a 32-bit Git (mingw32) has libbrotlidec.dll under $Root; no 32-bit package is prepared, so nothing is replaced" }
  throw "expected exactly one of mingw64/ucrt64 with bin\libbrotlidec.dll under $Root, found none"
}
# Version of the Brotli this Git ships: curl -V when bin\curl.exe exists, else the known libbrotlidec.dll hash.
function Get-ShippedBrotli([string]$Bin, [string]$Prefix) {
  if (Test-Path -LiteralPath "$Bin\curl.exe") { return @{ Version = (Get-CurlBrotli "$Bin\curl.exe"); Source = 'curl' } }
  $h = (Get-FileHash -LiteralPath "$Bin\libbrotlidec.dll").Hash.ToLower()
  if ($shippedDec[$Prefix].ContainsKey($h)) { return @{ Version = $shippedDec[$Prefix][$h]; Source = 'hash' } }
  throw "no curl.exe in $Bin and its libbrotlidec.dll (SHA256 $h) is not a known Git for Windows build, so its version cannot be told; check by hand"
}
function Get-GitExe([string]$Root, [string]$Prefix) {
  foreach ($g in @("$Root\cmd\git.exe", "$Root\bin\git.exe", "$Root\$Prefix\bin\git.exe")) { if (Test-Path -LiteralPath $g -PathType Leaf) { return $g } }
  $null
}
# Refuse links: a junction / symlink on the way from Root to a DLL folder, or a DLL that is a symlink or a hard link,
# would make the write land outside Root (an elevated run could overwrite any file). Root itself must not be a link either.
function Assert-NoLinkPath([string]$Root, [string]$Dir) {
  $full = [IO.Path]::GetFullPath($Dir).TrimEnd('\')
  if (-not $full.StartsWith("$Root\", [StringComparison]::OrdinalIgnoreCase) -and $full -ine $Root) { throw "$Dir is not under $Root" }
  $p = $full
  while ($true) {
    if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$p is a link (junction or symbolic link); nothing is replaced. Pass the real folder" }
    if ($p -ieq $Root) { break }
    $p = Split-Path -Parent $p
    if (-not $p) { throw "$Dir is not under $Root" }
  }
  foreach ($n in $names) { Assert-NotLinkFile "$full\$n" -Root $Root }
}
# A symbolic link is refused. A hard link is allowed only when every name of the file is under Root: the Git for Windows
# installer hard-links the DLLs of bin and libexec\git-core. The new DLL is written as a new file (see the
# write loop), so the other names are never written through.
function Get-HardLinkNames([string]$File) {
  $out = & "$env:SystemRoot\System32\fsutil.exe" hardlink list $File 2>&1
  if ($LASTEXITCODE -ne 0) { throw "cannot list the hard links of $File (fsutil exit $LASTEXITCODE): $out" }
  $drive = [IO.Path]::GetPathRoot($File).TrimEnd('\')
  @($out | Where-Object { "$_".Trim() } | ForEach-Object { $drive + "$_".Trim() })
}
function Assert-NotLinkFile([string]$File, [string]$Root = '', [switch]$AllowHardLink) {
  if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { return }
  $i = Get-Item -LiteralPath $File -Force
  if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$File is a link; nothing is replaced" }
  if ($AllowHardLink -or "$($i.LinkType)" -ne 'HardLink') { return }
  foreach ($h in (Get-HardLinkNames $File)) {
    if (-not $h.StartsWith("$Root\", [StringComparison]::OrdinalIgnoreCase)) { throw "$File is a hard link that is also $h (outside $Root); nothing is replaced" }
  }
}
# The link checks run before the writes, so another process could still swap a folder for a junction in between (TOCTOU).
# That only matters when this script runs elevated and someone without admin rights can change the folders: then they could
# make an elevated write land anywhere. So an elevated run is allowed only for a Git under Program Files whose folders
# (GitRoot down to every place that is written or run) give no write, delete or permission rights to non-admins and are owned
# by an admin. A Git in the user's own folders (PortableGit, MinGit) needs no elevation: run it in a normal PowerShell, where
# a swapped folder gives nothing the user did not already have.
$adminSids = @('S-1-5-32-544','S-1-5-18','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')   # Administrators, SYSTEM, TrustedInstaller
function Test-IsElevated { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
# rights that let a non-admin replace, rename, re-link or re-permission the folder: write data / add subfolder / delete child /
# write attributes / delete / change permissions / take ownership, and the generic all / write bits
$modifyMask = 0x2 -bor 0x4 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
function Get-NonAdminModifiers([string]$Dir) {
  $acl = Get-Acl -LiteralPath $Dir
  $who = @()
  $owner = (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
  if ($adminSids -notcontains $owner) { $who += "owner $($acl.Owner)" }
  foreach ($a in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($a.AccessControlType -ne 'Allow') { continue }
    if ($a.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }   # does not apply to this folder
    if (([int64]$a.FileSystemRights -band $modifyMask) -eq 0) { continue }
    if ($adminSids -contains $a.IdentityReference.Value) { continue }
    $who += "$($a.IdentityReference.Value) ($($a.FileSystemRights))"
  }
  $who
}
function Assert-SafeElevatedTree([string]$Root, [string[]]$Dirs) {
  $pf = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
  if (-not @($pf | Where-Object { $Root.StartsWith("$_\", [StringComparison]::OrdinalIgnoreCase) }).Count) {
    throw "this PowerShell is elevated, but $Root is not under Program Files. Run this in a normal (not elevated) PowerShell: the folder is yours, so no elevation is needed"
  }
  # every folder from each written place up to the Program Files folder itself: a non-admin who can rename or delete
  # any of them (also above GitRoot) could swap the whole tree after the check
  $top = @($pf | Where-Object { $Root.StartsWith("$_\", [StringComparison]::OrdinalIgnoreCase) })[0]
  foreach ($d in @($Root) + $Dirs) {
    $p = [IO.Path]::GetFullPath($d).TrimEnd('\')
    while ($true) {
      if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$p is a link; nothing is replaced" }
      $who = @(Get-NonAdminModifiers $p)
      if ($who.Count) { throw "this PowerShell is elevated, but non-admins can change $p ($($who -join '; ')). Nothing is replaced; fix the permissions or update this Git instead" }
      if ($p -ieq $top) { break }
      $p = Split-Path -Parent $p
      if (-not $p) { throw "$d is not under $top" }
    }
  }
}
# git.exe is run (elevated, for --version and ls-remote), so no junction or symbolic link may lead to it: that could make
# this script run another program. A hard link is fine here (it runs the same file; the installer links cmd\git.exe).
function Assert-NoLinkGitExe([string]$Root, [string]$GitExe) {
  Assert-NoLinkPath $Root (Split-Path -Parent $GitExe)
  Assert-NotLinkFile $GitExe -AllowHardLink
}
if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced by Test-Helpers.ps1: only the functions are wanted

$prefix = Resolve-GitBrotliPrefix $GitRoot; $set = $sets[$prefix]
$elevated = Test-IsElevated
if (Test-Path -LiteralPath "$GitRoot\mingw32\bin\libbrotlidec.dll") { "NOTE: $GitRoot\mingw32 (32-bit) also has libbrotlidec.dll; it is not touched" }
# Only a Git tree is changed: another MSYS2-based app with the same layout (a wrong -GitRoot) is refused.
$gitExe = Get-GitExe $GitRoot $prefix
if (-not $gitExe) {
  if (-not $Check) { throw "no git.exe in $GitRoot\cmd, $GitRoot\bin or $GitRoot\$prefix\bin: this is not a Git tree, so nothing is replaced" }
  "WARNING: no git.exe under $GitRoot; this is not recognized as a Git tree, and a run without -Check would refuse it"
} else { Assert-NoLinkGitExe $GitRoot $gitExe }
# read the new DLLs once and verify the bytes in memory; those same bytes are written later (no swap between check and use)
function Read-VerifiedDlls([string]$dir) {
  $r = @{}
  foreach ($n in $names) {
    if (-not (Test-Path -LiteralPath "$dir\$n" -PathType Leaf)) { return $null }
    $b = [IO.File]::ReadAllBytes("$dir\$n")
    if ((Get-Sha256 $b) -ne $set.hash[$n]) { throw "hash mismatch: $dir\$n" }
    $r[$n] = $b
  }
  $r
}
# only called once a replacement is known to be needed (not for -Check, not when every place is already fine)
function Get-NewDlls {
  $got = if (Test-Path -LiteralPath $set.dir) { Read-VerifiedDlls $set.dir } else { $null }
  if ($got) { return $got }
  $url = "https://repo.msys2.org/mingw/$prefix/$($set.pkg)-any.pkg.tar.zst"
  Write-Host "fetching $url"   # Write-Host: the function's output is the DLL table
  $tmp = Join-Path $env:TEMP ('emudhra-brotli-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    & "$env:SystemRoot\System32\curl.exe" -sSfL --proto '=https' --max-time 300 -o "$tmp\pkg.tar.zst" $url
    if ($LASTEXITCODE -ne 0) { throw "download failed (curl exit $LASTEXITCODE): $url" }
    if ((Get-Sha256 ([IO.File]::ReadAllBytes("$tmp\pkg.tar.zst"))) -ne $set.pkgHash) { throw "package SHA256 mismatch: $url" }
    New-Item -ItemType Directory -Path "$tmp\x" | Out-Null
    & "$env:SystemRoot\System32\tar.exe" -x -f "$tmp\pkg.tar.zst" -C "$tmp\x" ($names | ForEach-Object { "$prefix/bin/$_" })
    if ($LASTEXITCODE -ne 0) { throw "tar could not extract the DLLs (exit $LASTEXITCODE)" }
    $got = Read-VerifiedDlls "$tmp\x\$prefix\bin"
    if (-not $got) { throw "the package does not contain all three DLLs" }
    New-Item -ItemType Directory -Path $set.dir -Force | Out-Null
    foreach ($n in $names) { [IO.File]::WriteAllBytes("$($set.dir)\$n", $got[$n]) }
    Write-Host "saved the verified DLLs to $($set.dir)"
    return $got
  } finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
$bin = "$GitRoot\$prefix\bin"
$dirs = @()
foreach ($d in @($bin, "$GitRoot\$prefix\libexec\git-core")) {
  $have = @($names | Where-Object { Test-Path -LiteralPath "$d\$_" })
  if ($have.Count -eq 0 -and $d -ne $bin) { continue }
  if ($have.Count -ne $names.Count) { throw "$d has only some Brotli DLLs ($($have -join ', ')); check by hand" }
  Assert-NoLinkPath $GitRoot $d
  $dirs += $d
}
if ($elevated) { Assert-SafeElevatedTree $GitRoot $dirs }   # before anything is read for the version or written
$binHash = Get-SetHashes $bin
$binIsOurs = Test-SameSet $binHash $set.hash
$haveCurl = Test-Path -LiteralPath "$bin\curl.exe"
$shipped = if ($binIsOurs) { $null } else { (Get-ShippedBrotli $bin $prefix).Version }
if (-not $haveCurl) { "no curl.exe in $bin (MinGit style): the version comes from the libbrotlidec.dll hash, and the result is verified by DLL hashes" }
$binIsShippedNew = (-not $binIsOurs) -and ([version]$shipped -ge [version]'1.2.1')
$todo = @()
foreach ($d in $dirs) {
  $h = Get-SetHashes $d
  if (Test-SameSet $h $set.hash) { "$d : already MSYS2 brotli 1.2.1-1"; continue }
  if ($binIsOurs) {
    # bin was replaced by an earlier run (which only did bin); identify this copy by that run's backup
    $match = Get-ChildItem -LiteralPath $GitRoot -Directory -Filter '_emudhra_backup_brotli-*' | ForEach-Object { $_; Get-ChildItem -LiteralPath $_.FullName -Directory } |
      Where-Object { (Test-Path -LiteralPath "$($_.FullName)\libbrotlicommon.dll") -and (Test-SameSet (Get-SetHashes $_.FullName) $h) } | Select-Object -First 1
    if (-not $match) { throw "$d has Brotli DLLs that match neither 1.2.1-1 nor an earlier backup; check by hand" }
    $root = if ($match.Name -like '_emudhra_backup_brotli-*') { $match.Name } else { $match.Parent.Name }
    $v = [regex]::Match($root, '^_emudhra_backup_brotli-(\d+\.\d+\.\d+)')
    if (-not $v.Success -or [version]$v.Groups[1].Value -ge [version]'1.2.1') { throw "cannot tell the version of $d from $($match.FullName)" }
    $shipped = $v.Groups[1].Value
    "$d : still brotli/$shipped (same as $($match.FullName))"; $todo += $d; continue
  }
  if (-not (Test-SameSet $h $binHash)) { throw "$d has Brotli DLLs that differ from $bin and from 1.2.1-1; check by hand" }
  if ($binIsShippedNew) { "$d : Git ships brotli/$shipped; nothing to do"; continue }
  "$d : brotli/$shipped, will replace"; $todo += $d
}
if ($todo.Count -eq 0) { 'Nothing to replace.'; return }
if ($Check) { 'Check only: nothing changed.'; return }
if ($elevated) { Assert-SafeElevatedTree $GitRoot $todo }   # before anything is written (again before the copy)
$busy = Get-Process | Where-Object { $_.Path -and [IO.Path]::GetFullPath($_.Path).StartsWith("$GitRoot\", [StringComparison]::OrdinalIgnoreCase) }
if ($busy) { throw "close these first: $(($busy | ForEach-Object { "$($_.Name)($($_.Id))" }) -join ', ')" }
# fail before touching anything when this PowerShell may not write there (C:\Program Files needs an elevated PowerShell):
# a new file in the Git folder (backup) and in each place, and each DLL opened for writing without changing it
# (catches a read-only attribute, a deny ACL on the file, or a DLL that a running program has loaded)
foreach ($d in @($GitRoot) + $todo) {
  $probe = "$d\_emudhra_write_test_$([guid]::NewGuid().ToString('N')).tmp"
  try { [IO.File]::WriteAllBytes($probe, [byte[]]@()); Remove-Item -LiteralPath $probe -Force }
  catch { throw "cannot write to $d (run this in an elevated PowerShell): $($_.Exception.Message)" }
}
foreach ($d in $todo) { foreach ($n in $names) {
  try { $fs = [IO.File]::Open("$d\$n", [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None); $fs.Close() }
  catch { throw "cannot overwrite $d\$n (read-only, in use, or no permission; run elevated and close programs using Git): $($_.Exception.Message)" }
} }
$newBytes = Get-NewDlls

foreach ($d in $todo) { Assert-NoLinkPath $GitRoot $d }   # again right before writing
if ($elevated) { Assert-SafeElevatedTree $GitRoot $todo }
Assert-NoLinkGitExe $GitRoot $gitExe                      # and before running git.exe
$git = & $gitExe --version
$bk = "$GitRoot\_emudhra_backup_brotli-$shipped-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $bk | Out-Null   # no -Force: a fresh, unique folder every run
$done = @()
try {
  foreach ($d in $todo) {
    $sub = "$bk\" + ($d.Substring($GitRoot.Length + 1) -replace '\\','_')
    New-Item -ItemType Directory -Path $sub | Out-Null
    foreach ($n in $names) { Copy-Item -LiteralPath "$d\$n" -Destination "$sub\$n" }
    if (-not (Test-SameSet (Get-SetHashes $sub) (Get-SetHashes $d))) { throw "backup copy differs in $sub" }
    $done += ,@($d, $sub)
    # write a new file and put it in place instead of writing into the old one: a hard-linked DLL (bin and libexec\git-core
    # share one file in an installed Git) must not change in the other place before that place is backed up
    foreach ($n in $names) {
      $tmpDll = "$d\$n.emudhra-new-$([guid]::NewGuid().ToString('N'))"
      [IO.File]::WriteAllBytes($tmpDll, $newBytes[$n])
      try { [IO.File]::Delete("$d\$n"); [IO.File]::Move($tmpDll, "$d\$n") }
      finally { if (Test-Path -LiteralPath $tmpDll) { Remove-Item -LiteralPath $tmpDll -Force -ErrorAction SilentlyContinue } }
    }
    if (-not (Test-SameSet (Get-SetHashes $d) $set.hash)) { throw "copy did not take effect in $d" }
  }
  if ($haveCurl) {
    $after = Get-CurlBrotli "$bin\curl.exe"
    if ($after -ne '1.2.1') { throw "curl reports brotli/$after after the copy" }
    $verified = "curl now reports brotli/$after"
  } else {
    # no curl.exe to ask: check every replaced place against the MSYS2 package hashes once more
    foreach ($d in $todo) { if (-not (Test-SameSet (Get-SetHashes $d) $set.hash)) { throw "DLL hashes in $d do not match $($set.pkg) after the copy" } }
    $verified = "curl.exe is absent, so the replaced DLLs were verified by SHA256 against $($set.pkg) instead of curl -V"
  }
} catch {
  "FAILED: $_ -- restoring originals"
  $err = $_; $left = @()
  foreach ($p in $done) { foreach ($n in $names) {
    try {
      if ((Test-Path -LiteralPath "$($p[0])\$n") -and (Get-FileHash -LiteralPath "$($p[0])\$n").Hash -eq (Get-FileHash -LiteralPath "$($p[1])\$n").Hash) { continue }
      Copy-Item -LiteralPath "$($p[1])\$n" -Destination "$($p[0])\$n" -Force
    } catch { $left += "$($p[0])\$n" } } }
  # the contents come back; places that were hard links of each other come back as separate files with the same bytes
  if ($left) { "NOT RESTORED (copy these back from $bk by hand): $($left -join ', ')" } else { "Original contents restored (hard links between places are not re-created; the DLLs work the same); backup kept in $bk" }
  throw $err
}
$verified
& $gitExe ls-remote https://github.com/git/git.git HEAD
if ($LASTEXITCODE -ne 0) { "WARNING: git ls-remote failed (exit $LASTEXITCODE; network?). The DLLs stay replaced; originals are in $bk" }
try {
  Add-Content -Encoding utf8 -LiteralPath $LogFile -Value "$(Get-Date -Format s) CHANGE (Brotli CVE-2026-111497 mitigation, user-approved) $git at $GitRoot : replaced libbrotli{common,dec,enc}.dll brotli/$shipped with MSYS2 $($set.pkg) in: $($todo -join '; '). Originals in $bk (one subfolder per place). $verified. Revert: copy them back. A Git update will overwrite this."
} catch { "WARNING: could not write $LogFile ($_). Record this change by hand: originals in $bk" }
'Done.'
