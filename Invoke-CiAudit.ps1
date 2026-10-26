# Read-only check of GitHub repositories for the CI/CD attacks of Aug-Oct 2026 (runbook 3.4):
#   GhostAction-style secret theft in workflows, LiteLLM 1.107.0, the ChainDrop / tensorlake 0.5.144 worm (it also plants
#   .claude/settings.json and .vscode/tasks.json), plus risky settings (pull_request_target, toJSON(secrets), actions not
#   pinned by SHA, webhooks, deploy keys), run actors and commit authors since -Since.
# Only GET requests through gh. Secret VALUES are never read (only names and dates). File contents are matched but never
# written out: findings carry a path, a line number, a package version or a host name only.
# Run once per GitHub account (not once per PC). Results stay in -OutDir; never commit them or send them anywhere.
#   .\Invoke-CiAudit.ps1                                  # the gh account and every organization it belongs to
#   .\Invoke-CiAudit.ps1 -Owners me,some-org              # only these
#   .\Invoke-CiAudit.ps1 -KnownActors claude,my-ci-bot    # extra accounts whose commits and runs are expected
param([string[]]$Owners, [string[]]$KnownActors = @(), [string]$Since = '2026-08-31T00:00:00Z',
      [string]$OutDir = (Join-Path $HOME 'emudhra-audit\ci-audit'))
$ErrorActionPreference = 'Stop'
# powershell -File passes "-Owners a,b" as one string: split on commas
$Owners = @($Owners | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$KnownActors = @($KnownActors | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$gh = @(Get-Command gh.exe -ErrorAction SilentlyContinue | ForEach-Object Source) + @("$env:ProgramFiles\GitHub CLI\gh.exe") |
  Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $gh) { throw 'gh (GitHub CLI) not found. Install it and run: gh auth login' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
# keep the previous results and start clean (Export-Csv of an empty list writes nothing, so old rows would survive)
$old = @('ci-repos.csv', 'ci-findings.csv' | ForEach-Object { Join-Path $OutDir $_ } | Where-Object { Test-Path -LiteralPath $_ })
if ($old) { $prev = Join-Path $OutDir ('prev-' + (Get-Date -Format 'yyyyMMdd-HHmmss')); New-Item -ItemType Directory -Path $prev | Out-Null; $old | Move-Item -Destination $prev -ErrorAction Stop; "previous results moved to $prev" }

function Invoke-Gh([string[]]$ArgList) {
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $o = & $gh @ArgList 2>&1; $rc = $LASTEXITCODE; $ErrorActionPreference = $prev
  [pscustomobject]@{ Ok = ($rc -eq 0); Text = (($o | ForEach-Object { "$_" }) -join "`n") }
}
function Get-GhJson([string]$Path) {
  # one object (not paged). Returns @{ Ok; Data; Error }
  $r = Invoke-Gh @('api', '-H', 'Accept: application/vnd.github+json', $Path)
  if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Data = $null; Error = $r.Text } }
  [pscustomobject]@{ Ok = $true; Data = ($r.Text | ConvertFrom-Json); Error = '' }
}
function Get-GhList([string]$Path, [string]$Property) {
  # every page (gh --paginate --slurp gives an array of pages). $Property: the array inside each page object (e.g. 'secrets').
  # PS 5.1 emits a JSON array as one object, so pages and items are unrolled with ForEach-Object.
  $r = Invoke-Gh @('api', '-H', 'Accept: application/vnd.github+json', '--paginate', '--slurp', $Path)
  if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Items = @(); Error = $r.Text } }
  $pages = @($r.Text | ConvertFrom-Json | ForEach-Object { $_ })
  $items = @(foreach ($p in $pages) { if ($Property) { $p.$Property | ForEach-Object { $_ } } else { $p | ForEach-Object { $_ } } })
  [pscustomobject]@{ Ok = $true; Items = @($items | Where-Object { $_ }); Error = '' }
}
function Get-GhRaw([string]$Repo, [string]$Path, [string]$Ref) {
  # the file itself (raw media type: works above the 1 MB limit of the JSON contents response)
  $r = Invoke-Gh @('api', '-H', 'Accept: application/vnd.github.raw', "repos/$Repo/contents/$(ConvertTo-UrlPath $Path)?ref=$([Uri]::EscapeDataString($Ref))")
  [pscustomobject]@{ Ok = $r.Ok; Text = $(if ($r.Ok) { $r.Text } else { '' }); Error = $(if ($r.Ok) { '' } else { $r.Text }) }
}
function Get-LineNo([string]$Text, [int]$Index) { ($Text.Substring(0, $Index) -split "`n").Count }
function ConvertTo-UrlPath([string]$Path) { (($Path -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/' }
function Test-PinnedVersion([string]$Text, [string]$Package, [string]$Version) {
  # Same rule as Test-AuditPinnedVersion in Test-Emudhra.Helpers.ps1: the version must belong to the package's own entry
  # (same line, or a "version" field within 4 lines before a blank line, '}' or '[').
  $pkg = [regex]::Escape($Package); $ver = [regex]::Escape($Version); $lines = $Text -split "`r?`n"
  for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -notmatch "(?i)(?<![A-Za-z0-9_-])$pkg(?![A-Za-z0-9_-])") { continue }
    # a range (>=, ^, ~, <, !=, *, ||) does not fix the version: only an exact pin on the same line counts
    $sm = [regex]::Match($lines[$i], "(?i)(?<![A-Za-z0-9_-])$pkg(?![A-Za-z0-9_-])([^,;}\r\n]{0,80}?)(?<![0-9.])$ver(?![0-9A-Za-z.+-])")
    if ($sm.Success -and $sm.Groups[1].Value -notmatch '[<>^~!*]|\|\|') { return $true }   # stop at , ; } (the next entry on the same line; a { right after the name opens its own entry)
    for ($j = $i + 1; $j -le [Math]::Min($i + 4, $lines.Count - 1); $j++) {
      $l = $lines[$j]
      # stop at the end of the entry, or where a nested object starts (its versions belong to other packages)
      if ($l -match '^\s*$' -or $l -match '[{}]' -or $l -match '^\s*\[') { break }
      # the first version field is the package's own version: decide on it and stop
      $vm = [regex]::Match($l, '^\s*"?version"?\s*[:=]?\s*"?([^"\s,]+)"?\s*,?\s*$')
      if ($vm.Success) { if ($vm.Groups[1].Value -eq $Version) { return $true } else { break } }
    }
  }
  $false
}

$login = (Invoke-Gh @('api', 'user', '--jq', '.login')).Text.Trim()
if (-not $login -or $login -match '\s') { throw "gh is not logged in: $login" }
$rows = [Collections.Generic.List[object]]::new(); $findings = [Collections.Generic.List[object]]::new()
function Add-F($Repo, $Level, $What, $Detail) { $findings.Add([pscustomobject]@{ Repo = $Repo; Level = $Level; What = $What; Detail = "$Detail" }) }
if (-not $Owners) {
  $orgs = Get-GhList 'user/orgs?per_page=100'
  if (-not $orgs.Ok) { Add-F $login 'ERROR' 'organization list failed (organizations not checked)' $orgs.Error }
  $Owners = @($login) + @($orgs.Items | ForEach-Object login)
}
$known = @($login, 'dependabot[bot]', 'github-actions[bot]', 'renovate[bot]') + $KnownActors
$ioc = 'AKIA_CTX_START|c=monami|193\.32\.204\.199|45\.139\.104\.115|170\.39\.218\.2|oast\.fun'
$iocNames = 'security-audit.yml', 'github_actions_security.yml', 'security-check.yml'
$repoLimit = 10000

$repos = foreach ($o in $Owners) {
  $r = Invoke-Gh @('repo', 'list', $o, '--limit', "$repoLimit", '--json', 'nameWithOwner,isPrivate,isArchived,isFork,defaultBranchRef,pushedAt')
  if (-not $r.Ok) { Add-F $o 'ERROR' 'repo list failed (owner not checked)' $r.Text; continue }
  $list = @($r.Text | ConvertFrom-Json | ForEach-Object { $_ })
  if ($list.Count -ge $repoLimit) { Add-F $o 'ERROR' "repo list hit the limit of $repoLimit (some repositories not checked)" '' }
  $list
}
$repos = @($repos | Where-Object { $_ })
"account: $login / owners: $($Owners -join ', ') / repositories: $($repos.Count)"
$i = 0
foreach ($repo in $repos) {
  $i++; $n = $repo.nameWithOwner; $br = $repo.defaultBranchRef.name
  Write-Host ("[{0}/{1}] {2}" -f $i, $repos.Count, $n)
  $row = [ordered]@{ Repo = $n; Private = $repo.isPrivate; Archived = $repo.isArchived; Fork = $repo.isFork; Pushed = $repo.pushedAt; Workflows = 0
                     Unpinned = 0; PRTarget = 0; RunsSince = ''; OtherActors = ''; Secrets = ''; Hooks = ''; DeployKeys = ''; Error = '' }
  function Fail($What, $Err) { $row.Error += "$What; "; Add-F $n 'ERROR' "$What failed (not checked)" (($Err -split "`n")[0]) }
  # an empty repository has no files or commits, but may still have secrets, webhooks and deploy keys (step 6 runs anyway)
  if (-not $br) { $row.Error = 'empty repository (files and history not applicable); ' }
  else {
  # 1) the default branch's file list
  $tree = Get-GhJson "repos/$n/git/trees/$([Uri]::EscapeDataString($br))?recursive=1"
  if (-not $tree.Ok) { Fail 'file list' $tree.Error }
  elseif ($tree.Data.truncated) { Add-F $n 'ERROR' 'file list truncated by GitHub (large repository: files not all checked)' '' }
  $paths = @($tree.Data.tree | Where-Object { $_ -and $_.type -eq 'blob' } | ForEach-Object { $_.path })
  foreach ($p in $paths) {
    if ($p -like '.github/workflows/*' -and $iocNames -contains (Split-Path $p -Leaf)) { Add-F $n 'CHECK' 'workflow file name used by GhostAction-style attacks (check who added it)' $p }
    if ($p -match '(^|/)\.claude/settings(\.local)?\.json$' -or $p -match '(^|/)\.vscode/tasks\.json$') {
      $cm = Get-GhList "repos/$n/commits?path=$([Uri]::EscapeDataString($p))&per_page=100"; if (-not $cm.Ok) { Fail "history of $p" $cm.Error }
      $authors = @($cm.Items | ForEach-Object { if ($_.author) { $_.author.login } else { "$($_.commit.author.name)(no account)" } } | Sort-Object -Unique)
      $c = Get-GhRaw $n $p $br; if (-not $c.Ok) { Fail "content of $p" $c.Error }
      $auto = @(); if ($c.Text -match '"hooks"\s*:') { $auto += 'hooks' }; if ($c.Text -match '"runOn"\s*:\s*"folderOpen"') { $auto += 'runOn=folderOpen' }
      $others = @($authors | Where-Object { $known -notcontains ($_ -replace '\(no account\)$','') })
      $recent = @($cm.Items | Where-Object { $_.commit.author.date -ge $Since })
      $level = if ($c.Text -match $ioc) { 'HIGH' } elseif ($c.Text -match '(?i)tensorlake' -or $others.Count -or $recent.Count) { 'CHECK' } else { 'INFO' }
      $last = if ($cm.Items) { $cm.Items[0].commit.author.date } else { '' }
      Add-F $n $level 'file type the tensorlake worm plants' "$p authors=$($authors -join ',') last=$last changed-since=$($recent.Count) auto=$($auto -join ',')"
    }
  }
  # 2) workflow contents (matched, never written out)
  $wf = @($paths | Where-Object { $_ -like '.github/workflows/*' -and $_ -match '\.ya?ml$' }); $row.Workflows = $wf.Count
  foreach ($p in $wf) {
    $c = Get-GhRaw $n $p $br; if (-not $c.Ok) { Fail "content of $p" $c.Error; continue }
    $t = $c.Text
    $m = [regex]::Match($t, $ioc); if ($m.Success) { Add-F $n 'HIGH' "attacker string in workflow ($($m.Value))" "$($p):$(Get-LineNo $t $m.Index)" }
    $m = [regex]::Match($t, 'toJSON\(\s*secrets\s*\)'); if ($m.Success) { Add-F $n 'CHECK' 'workflow passes all secrets at once (toJSON(secrets)); check where they go' "$($p):$(Get-LineNo $t $m.Index)" }
    foreach ($m in [regex]::Matches($t, '(?m)^.*\b(curl|wget|Invoke-WebRequest|iwr)\b.*\$\{\{\s*secrets\..*$')) { Add-F $n 'CHECK' 'secret sent with a web request (check the destination)' "$($p):$(Get-LineNo $t $m.Index)" }
    if ($t -match '(?m)^\s*pull_request_target\s*:|on:\s*\[?[^\n]*pull_request_target') { $row.PRTarget++; Add-F $n 'CHECK' 'pull_request_target trigger (runs with secrets on PRs from forks)' $p }
    foreach ($m in [regex]::Matches($t, '(?m)^\s*-?\s*uses:\s*([^\s#]+)')) {
      $u = $m.Groups[1].Value.Trim('"', "'"); if ($u -like './*' -or $u -like 'docker://*') { continue }
      if ($u -notmatch '@[0-9a-f]{40}$') { $row.Unpinned++ }
    }
    if ($t -match '(?i)litellm') { Add-F $n 'CHECK' 'workflow installs or mentions litellm (check the version)' $p }
  }
  # 3) dependency manifests: the compromised releases are HIGH, any other mention is CHECK
  foreach ($p in @($paths | Where-Object { (Split-Path $_ -Leaf) -match '^(requirements.*\.txt|pyproject\.toml|uv\.lock|poetry\.lock|Pipfile(\.lock)?|package\.json|package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$' })) {
    $c = Get-GhRaw $n $p $br; if (-not $c.Ok) { Fail "content of $p" $c.Error; continue }
    foreach ($pkg in @(@('litellm','1.107.0'), @('tensorlake','0.5.144'))) {
      if ($c.Text -notmatch "(?i)\b$($pkg[0])\b") { continue }
      if (Test-PinnedVersion $c.Text $pkg[0] $pkg[1]) { Add-F $n 'HIGH' "$($pkg[0]) $($pkg[1]) (compromised release)" $p }
      else { Add-F $n 'CHECK' "$($pkg[0]) dependency (check the version and pinning)" $p }
    }
  }
  # 4) workflow runs since $Since: who started them (newest 100)
  $runs = Get-GhJson "repos/$n/actions/runs?per_page=100&created=%3E%3D$Since"
  if (-not $runs.Ok) { Fail 'workflow runs' $runs.Error } else {
    $row.RunsSince = $runs.Data.total_count
    $wr = @($runs.Data.workflow_runs | Where-Object { $_ })
    $actors = @($wr | ForEach-Object { $_.actor.login; $_.triggering_actor.login } | Where-Object { $_ } | Sort-Object -Unique)
    $other = @($actors | Where-Object { $known -notcontains $_ }); $row.OtherActors = $other -join ','
    if ($other) { Add-F $n 'CHECK' "workflow runs started by accounts other than $login / known bots" ($other -join ', ') }
    foreach ($w in @($wr | ForEach-Object { $_.path } | Sort-Object -Unique)) { if ($iocNames -contains (Split-Path $w -Leaf)) { Add-F $n 'CHECK' 'a run of a GhostAction-style workflow file name' $w } }
    if ($runs.Data.total_count -gt 100) { Add-F $n 'INFO' 'more than 100 runs since the start date' 'only the newest 100 were inspected' }
  }
  # 5) commits since $Since that touched workflows or worm-planted files, grouped by author. The account's own name without a
  #    linked GitHub account (a local git identity) is INFO; any other author is CHECK.
  foreach ($p in '.github/workflows', '.claude', '.vscode') {
    $cm = Get-GhList "repos/$n/commits?path=$([Uri]::EscapeDataString($p))&since=$([Uri]::EscapeDataString($Since))&per_page=100"; if (-not $cm.Ok) { Fail "commits to $p" $cm.Error; continue }
    foreach ($g in @($cm.Items | Group-Object { if ($_.author) { $_.author.login } else { "$($_.commit.author.name) <no GitHub account>" } })) {
      $name = $g.Name -replace ' <no GitHub account>$',''
      $level = if ($known -contains $g.Name) { $null } elseif ($known -contains $name) { 'INFO' } else { 'CHECK' }
      if (-not $level) { continue }
      $dates = @($g.Group | ForEach-Object { $_.commit.author.date } | Sort-Object)
      Add-F $n $level "commits to $p by $($g.Name)" "$($g.Count) commits $($dates[0])..$($dates[-1])"
    }
  }
  }   # end of the checks that need a default branch
  # 6) Actions secret names and dates (never values), webhooks (host only) and deploy keys
  $s = Get-GhList "repos/$n/actions/secrets?per_page=100" 'secrets'
  if (-not $s.Ok) { Fail 'secret names' $s.Error } else { $row.Secrets = (@($s.Items | ForEach-Object { "$($_.name)($(([datetime]$_.updated_at).ToString('yyyy-MM-dd')))" }) -join ',') }
  $h = Get-GhList "repos/$n/hooks?per_page=100"
  if (-not $h.Ok) { Fail 'webhooks' $h.Error } else {
    $row.Hooks = $h.Items.Count
    foreach ($x in $h.Items) { $hostName = try { ([Uri]$x.config.url).Host } catch { '(unparsable url)' }; Add-F $n 'CHECK' 'webhook' "host=$hostName events=$($x.events -join ',') created=$($x.created_at) active=$($x.active)" }
  }
  $k = Get-GhList "repos/$n/keys?per_page=100"
  if (-not $k.Ok) { Fail 'deploy keys' $k.Error } else { $row.DeployKeys = $k.Items.Count; foreach ($x in $k.Items) { Add-F $n 'CHECK' 'deploy key' "$($x.title) read_only=$($x.read_only) created=$($x.created_at)" } }
  $rows.Add([pscustomobject]$row)
}
$rows | Export-Csv (Join-Path $OutDir 'ci-repos.csv') -NoTypeInformation -Encoding UTF8
$findings | Export-Csv (Join-Path $OutDir 'ci-findings.csv') -NoTypeInformation -Encoding UTF8
$cnt = { param($l) @($findings | Where-Object Level -eq $l).Count }
"done: repos=$($rows.Count) HIGH=$(& $cnt 'HIGH') CHECK=$(& $cnt 'CHECK') ERROR=$(& $cnt 'ERROR') INFO=$(& $cnt 'INFO') -> $OutDir"
if (& $cnt 'ERROR') { Write-Warning 'ERROR = not checked (permission, rate limit, network). Those parts are unverified, not clean.' }
$findings | Where-Object { $_.Level -in 'HIGH','CHECK','ERROR' } | Sort-Object { @{HIGH=0;ERROR=1;CHECK=2}[$_.Level] } | ForEach-Object { "  $($_.Level) $($_.Repo): $($_.What) $($_.Detail)" }
"repositories with secrets and actions not pinned by SHA (consider pinning, or removing secrets of stopped repositories):"
$rows | Where-Object { $_.Secrets -and [int]$_.Unpinned -gt 0 } | ForEach-Object { "  $($_.Repo) private=$($_.Private) unpinned=$($_.Unpinned) secrets=$($_.Secrets)" }
