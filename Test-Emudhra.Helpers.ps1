#requires -Version 5.1
# ASCII source for Windows PowerShell 5.1. Dot-source to load; no automatic probes.

function Write-AuditUtf8 {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path,
          [AllowEmptyString()][string]$Text = '')
    $absolute = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($absolute)
    [void][IO.Directory]::CreateDirectory($parent)
    [IO.File]::WriteAllText($absolute, $Text, [Text.UTF8Encoding]::new($false))
}

function Get-AuditChainVerdict {
    [CmdletBinding()]
    param([bool]$Invoked, [bool]$Completed, [int]$PolicyErrors,
          [long]$StatusBits)
    if (-not $Invoked) { return 'UNKNOWN(callback not invoked)' }
    # SslPolicyErrors: 1=missing certificate; 2=name mismatch; 4=chain errors.
    if (($PolicyErrors -band 3) -ne 0) { return 'UNKNOWN(name or certificate missing)' }
    if ($PolicyErrors -eq 0 -and $StatusBits -eq 0 -and $Completed) {
        return 'ACCEPT'
    }
    $allowed = [long][Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot -bor
               [long][Security.Cryptography.X509Certificates.X509ChainStatusFlags]::PartialChain -bor
               [long][Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked -bor
               [long][Security.Cryptography.X509Certificates.X509ChainStatusFlags]::ExplicitDistrust
    # Any unrelated or unknown bit overrides REJECT (including mixed failures).
    if ($StatusBits -ne 0 -and ($StatusBits -band (-bnot $allowed)) -eq 0 -and
        $PolicyErrors -eq 4) { return "REJECT(chain flags=$StatusBits)" }
    return "UNKNOWN(policy=$PolicyErrors flags=$StatusBits completed=$Completed)"
}

function Test-AuditSelfCheckPass {
    # Self-check only (untrusted-root.badssl.com). An untrusted root can never have its revocation
    # checked, so Windows always adds RevocationStatusUnknown/OfflineRevocation to UntrustedRoot.
    # Target verdicts stay strict (Get-AuditChainVerdict); this relaxation applies to the self-check only.
    [CmdletBinding()]
    param([bool]$Invoked, [int]$PolicyErrors, [long]$StatusBits)
    $f = [Security.Cryptography.X509Certificates.X509ChainStatusFlags]
    $untrusted = [long]$f::UntrustedRoot
    $allowed = $untrusted -bor [long]$f::RevocationStatusUnknown -bor [long]$f::OfflineRevocation
    return ($Invoked -and $PolicyErrors -eq 4 -and ($StatusBits -band $untrusted) -ne 0 -and
            ($StatusBits -band (-bnot $allowed)) -eq 0)
}

function Initialize-AuditTlsProbe {
    if ('EmudhraAuditV1.TlsProbe' -as [type]) { return }
    # Validation callback is C#, not a PowerShell scriptblock: SslStream may invoke it on a thread
    # without a runspace, so a scriptblock callback is unreliable.
    Add-Type -TypeDefinition @'
using System;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
namespace EmudhraAuditV1 {
    public sealed class TlsResult {
        public bool Invoked;
        public bool Completed;
        public int PolicyErrors;
        public long StatusBits;
        public string ErrorType = "";
    }
    public static class TlsProbe {
        public static TlsResult Run(string host, int timeoutMs) {
            TlsResult result = new TlsResult();
            TcpClient tcp = null;
            SslStream stream = null;
            try {
                tcp = new TcpClient();
                IAsyncResult connection = tcp.BeginConnect(host, 443, null, null);
                try {
                    if (!connection.AsyncWaitHandle.WaitOne(timeoutMs))
                        throw new TimeoutException();
                    tcp.EndConnect(connection);
                } finally { connection.AsyncWaitHandle.Close(); }
                tcp.ReceiveTimeout = timeoutMs;
                tcp.SendTimeout = timeoutMs;
                RemoteCertificateValidationCallback cb = delegate(object sender,
                    X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
                    result.Invoked = true;
                    result.PolicyErrors = (int)errors;
                    result.StatusBits = 0;
                    if (chain != null) {
                        foreach (X509ChainStatus s in chain.ChainStatus)
                            // Cast via uint: (long)enum triggers CS0675, which PS 5.1 Add-Type treats as an error.
                            result.StatusBits |= (long)(uint)s.Status;
                    }
                    // Preserve validation: never accept an invalid certificate.
                    return errors == SslPolicyErrors.None;
                };
                stream = new SslStream(tcp.GetStream(), false, cb);
                IAsyncResult auth = stream.BeginAuthenticateAsClient(host,
                    new X509CertificateCollection(), SslProtocols.None, true, null, null);
                try {
                    if (!auth.AsyncWaitHandle.WaitOne(timeoutMs))
                        throw new TimeoutException();
                    stream.EndAuthenticateAsClient(auth);
                    result.Completed = true;
                } finally { auth.AsyncWaitHandle.Close(); }
            } catch (Exception e) {
                result.ErrorType = e.GetType().FullName;
            } finally {
                if (stream != null) stream.Dispose();
                if (tcp != null) tcp.Close();
            }
            return result;
        }
    }
}
'@ -ErrorAction Stop
}

function Test-AuditWindowsTls {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$HostName,
          [ValidateRange(1000,60000)][int]$TimeoutMs = 15000)
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Windows trust-store probe requires Windows.'
    }
    Initialize-AuditTlsProbe
    $raw = [EmudhraAuditV1.TlsProbe]::Run($HostName, $TimeoutMs)
    [pscustomobject]@{
        Verdict = Get-AuditChainVerdict -Invoked $raw.Invoked -Completed $raw.Completed -PolicyErrors $raw.PolicyErrors -StatusBits $raw.StatusBits
        Detail = "policy=$($raw.PolicyErrors); flags=$($raw.StatusBits); error=$($raw.ErrorType)"
        Invoked = $raw.Invoked
        PolicyErrors = $raw.PolicyErrors
        StatusBits = $raw.StatusBits
    }
}

function Get-AuditSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][object[]]$Rows,
          [Parameter(Mandatory=$true)][string]$Control,
          [Parameter(Mandatory=$true)][ValidateCount(1,100)][string[]]$Targets)
    if (@($Targets | Select-Object -Unique).Count -ne $Targets.Count) {
        throw 'Targets must be unique.'
    }
    foreach ($group in @($Rows | Group-Object Tool)) {
        # Claude edit (v2.6): module not installed on every row -> N/A, not UNKNOWN noise. Never FIXED.
        if (@($group.Group | Where-Object { $_.Verdict -ne 'NONE' }).Count -eq 0) {
            [pscustomobject]@{ Tool=$group.Name; Status='N/A'; Reason='Module not installed (not counted as FIXED).' }
            continue
        }
        $ctrl = @($group.Group | Where-Object { $_.Target -eq $Control })
        $status = 'UNKNOWN'
        $reason = 'Control missing, duplicated, or not ACCEPT.'
        # Claude edit (v2.11.5): an accepted target is a completed handshake on its own, so a single UNKNOWN control
        # (old uv cannot prove the control request) still gives VULNERABLE. FIXED always needs an ACCEPT control.
        if ($ctrl.Count -eq 1 -and $ctrl[0].Verdict -in @('ACCEPT','UNKNOWN')) {
            $ctrlOk = ($ctrl[0].Verdict -eq 'ACCEPT')
            $complete = $true
            $targetRows = @()
            foreach ($target in $Targets) {
                $matches = @($group.Group | Where-Object { $_.Target -eq $target })
                if ($matches.Count -ne 1) { $complete = $false }
                else { $targetRows += $matches[0] }
            }
            if (-not $complete) { if ($ctrlOk) { $reason = 'Target missing or duplicated.' } }
            elseif (@($targetRows | Where-Object { $_.Verdict -eq 'ACCEPT' }).Count -gt 0) {
                $status = 'VULNERABLE'
                $reason = if ($ctrlOk) { 'At least one target accepted.' } else { 'At least one target accepted (control UNKNOWN).' }
            } elseif (-not $ctrlOk) {
                # Control UNKNOWN and no target accepted: the control reason stays.
            } elseif (@($targetRows | Where-Object { $_.Verdict -eq 'REJECT' }).Count -eq $Targets.Count) {
                $status = 'FIXED'; $reason = 'Every expected target rejected.'
            } else { $reason = 'At least one target UNKNOWN or NONE.' }
        }
        [pscustomobject]@{ Tool=$group.Name; Status=$status; Reason=$reason }
    }
}

function Invoke-AuditWindowsTlsSet {
    [CmdletBinding()]
    param([string]$ControlHost = 'www.google.com',
          [string[]]$TargetHosts = @('dv-g3b-emudhra.we-have-a-problem.com', 'dv-g3b-aaa-emudhra.we-have-a-problem.com'),
          [switch]$KnownTlsInspection)
    if ($KnownTlsInspection) {
        throw 'TLS inspection detected: use an approved uninspected path; no FIXED result issued.'
    }
    $self = Test-AuditWindowsTls -HostName 'untrusted-root.badssl.com'
    $selfOk = Test-AuditSelfCheckPass -Invoked $self.Invoked -PolicyErrors $self.PolicyErrors -StatusBits $self.StatusBits
    $rows = foreach ($serverName in @($ControlHost) + $TargetHosts) {
        $probe = Test-AuditWindowsTls -HostName $serverName
        $verdict = ($probe.Verdict -split '\(', 2)[0]
        if (-not $selfOk) { $verdict = 'UNKNOWN' }
        [pscustomobject]@{ Tool='winstore:direct-sslstream'; Target=$serverName; Verdict=$verdict;
            Detail="selfcheck=$(if ($selfOk) { 'PASS' } else { 'FAIL' })($($self.Detail)); $($probe.Detail)" }
    }
    # Caller can export Rows and Summary separately; no implicit global results.
    [pscustomobject]@{
        Rows=@($rows)
        Summary=@(Get-AuditSummary -Rows @($rows) -Control $ControlHost -Targets $TargetHosts)
    }
}

function ConvertTo-AuditNativeArgument {
    param([AllowEmptyString()][string]$Value)
    # Windows CRT quoting; do not use Invoke-Expression or a shell.
    # Quote only when needed: some programs parse the raw command line themselves and do not strip
    # quotes from their own options (py.exe 3.13 reads "--list-paths" as an unknown Python option).
    # Without whitespace or a double quote, CRT parsing returns the value unchanged (backslashes are literal).
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    '"' + ([regex]::Replace(([regex]::Replace($Value, '(\\*)"', '$1$1\"')), '(\\+)$', '$1$1')) + '"'
}

function Invoke-AuditNativeProcess {
    # Run a native program without PowerShell's native-output handling. In Windows PowerShell 5.1,
    # "2>&1 | Out-String" turns stderr into ErrorRecords that are wrapped at console width
    # (e.g. "CRYPT_E_ REVOKED"), which breaks pattern matching. stdout/stderr are read as bytes
    # decoded with $Encoding (default: ANSI code page, which is what Schannel messages use).
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$FilePath,
          [string[]]$ArgumentList=@(),
          [ValidateRange(1000,180000)][int]$TimeoutMs=60000,
          [Text.Encoding]$Encoding=[Text.Encoding]::Default,
          [hashtable]$Environment=@{},
          [string]$WorkingDirectory='')
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = [IO.Path]::GetFullPath($FilePath)
    # The child otherwise inherits the process's current directory (not PowerShell's Set-Location). MSYS programs
    # create a real file for "-o NUL" there (e.g. a NUL file in a repository), so callers can pick a folder.
    if ($WorkingDirectory) { $psi.WorkingDirectory = [IO.Path]::GetFullPath($WorkingDirectory) }
    $psi.Arguments = (@($ArgumentList) | ForEach-Object { ConvertTo-AuditNativeArgument $_ }) -join ' '
    $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true
    $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
    $psi.StandardOutputEncoding=$Encoding; $psi.StandardErrorEncoding=$Encoding
    # A $null value removes the variable from the child's environment (an empty string would still define it).
    foreach ($key in $Environment.Keys) {
        if ($null -eq $Environment[$key]) { $psi.EnvironmentVariables.Remove($key) } else { $psi.EnvironmentVariables[$key]=[string]$Environment[$key] }
    }
    $proc=[Diagnostics.Process]::new(); $proc.StartInfo=$psi
    try {
        if (-not $proc.Start()) { throw 'Process did not start.' }
        $proc.StandardInput.Close()
        $stdout=$proc.StandardOutput.ReadToEndAsync()
        $stderr=$proc.StandardError.ReadToEndAsync()
        # One deadline covers the exit AND both pipes: a grandchild that inherited the pipes can keep
        # them open after the process itself has exited.
        $deadline=[DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        $exited=$proc.WaitForExit($TimeoutMs)
        $remaining=[Math]::Max(0,[int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $exited -or -not [Threading.Tasks.Task]::WaitAll(@($stdout,$stderr),$remaining)) {
            # Kill the whole tree (credential helpers etc.). Orphans whose parent already exited are not
            # reachable this way; the caller still gets a timeout instead of hanging.
            try { [void](& "$env:SystemRoot\System32\taskkill.exe" /PID $proc.Id /T /F 2>&1) } catch { }
            try { if (-not $proc.HasExited) { $proc.Kill() } } catch { }
            throw 'Process timeout.'
        }
        $proc.WaitForExit()
        [pscustomobject]@{ ExitCode=$proc.ExitCode; StdOut=$stdout.Result; StdErr=$stderr.Result }
    } finally { $proc.Dispose() }
}

function Invoke-AuditPythonProcess {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Python,
          [Parameter(Mandatory=$true)][string]$ProbeScript,
          [Parameter(Mandatory=$true)][string]$Url,
          [ValidateRange(1000,180000)][int]$TimeoutMs=90000)
    try {
        $result=Invoke-AuditNativeProcess -FilePath $Python -TimeoutMs $TimeoutMs -Encoding ([Text.UTF8Encoding]::new($false)) `
            -ArgumentList @([IO.Path]::GetFullPath($ProbeScript), $Url) -Environment @{ PYTHONIOENCODING='utf-8' }
    } catch {
        if ($_.Exception.Message -like '*timeout*') { throw 'Python process timeout.' }
        throw
    }
    # stderr is discarded on purpose: do not dump arbitrary stderr/secrets.
    if ($result.ExitCode -ne 0) { throw "Python probe exit=$($result.ExitCode)." }
    $data=$result.StdOut | ConvertFrom-Json -ErrorAction Stop
    foreach ($route in @('stdlib-ssl','certifi','requests')) {
        $found=@($data | Where-Object { $_.route -eq $route })
        if ($found.Count -ne 1 -or $found[0].verdict -notin @('ACCEPT','REJECT','UNKNOWN','NONE')) {
            throw "Malformed Python probe output: $route."
        }
    }
    return $data
}

# TLS failure classification for curl / Git (Schannel and OpenSSL builds). Only ASCII tokens are
# matched (error names, HRESULTs, OpenSSL texts): localized descriptions are not reliable.
# Unrelated failures (expiry, name mismatch, revocation check unavailable) are checked first.
function Get-AuditTlsPatterns {
    @{
        NotRelated='SEC_E_CERT_EXPIRED|0x80090328|SEC_E_WRONG_PRINCIPAL|0x80090322|CERT_E_EXPIRED|0x800B0101|' +
            'CERT_E_CN_NO_MATCH|0x800B010F|CRYPT_E_NO_REVOCATION_CHECK|0x80092012|CRYPT_E_REVOCATION_OFFLINE|0x80092013|' +
            'certificate has expired|not yet valid|does not match|no alternative certificate subject name|name mismatch'
        Reject='CRYPT_E_REVOKED|0x80092010|SEC_E_UNTRUSTED_ROOT|0x80090325|CERT_E_UNTRUSTEDROOT|0x800B0109|' +
            'CERT_E_CHAINING|0x800B010A|CERT_E_REVOKED|0x800B010C|unable to get local issuer|' +
            'self.signed certificate in certificate chain|certificate revoked'
    }
}

function Hide-AuditSecret {
    # Mask secrets before anything is saved: "<name containing password/token/secret/key>=<value>" (a quoted value is
    # masked with its quotes, also across line breaks) and URL user info. Over-masking (e.g. keyStore paths) is accepted.
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if (-not $Text) { return [string]$Text }
    # Quoted values may contain backslash escapes ("a\" b", a backslash before a line break) and line breaks.
    # A whole quoted argument that holds a secret option ("-Dx.password=a b") is masked as a whole first.
    # The name and its separator must both lie inside the same quotes (so '"password": "v"' is left to the rule below).
    $Text=$Text -replace '(?i)"(?=(?:\\[\s\S]|[^"\\])*?(?:password|passwd|pwd|token|secret|key)[^\s="]*[^\S"]*[=:])(?:\\[\s\S]|[^"\\])*"','<redacted>'
    $Text=$Text -replace '(?i)''(?=(?:\\[\s\S]|[^''\\])*?(?:password|passwd|pwd|token|secret|key)[^\s='']*[^\S'']*[=:])(?:\\[\s\S]|[^''\\])*''','<redacted>'
    $Text -replace '(?i)([^\s=]*(password|passwd|pwd|token|secret|key)[^\s=]*\s*[=:]\s*)("(?:\\[\s\S]|[^"\\])*"|''(?:\\[\s\S]|[^''\\])*''|\S+)','$1<redacted>' -replace '://[^/@\s]+@','://<redacted>@'
}

function Remove-AuditUrlText {
    # Tokens must come from the diagnostic, not from the requested URL echoed back in it.
    param([AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$Url)
    $t=[string]$Text
    if ($Url) {
        $t=$t.Replace($Url,'<url>').Replace($Url.TrimEnd('/'),'<url>')
        $uri=$null
        if ([Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$uri) -and $uri.Host) {
            $t=[regex]::Replace($t,[regex]::Escape($uri.Host),'<host>','IgnoreCase')
        }
    }
    $t
}

function Get-AuditCurlVerdict {
    [CmdletBinding()]
    param([int]$ExitCode, [AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$Url='')
    # 0 = success, 47 = redirect limit reached: the TLS handshake completed.
    if ($ExitCode -eq 0 -or $ExitCode -eq 47) { return 'ACCEPT' }
    # Schannel reports a revoked chain as 35 (handshake failure), an untrusted root as 60.
    if ($ExitCode -notin @(35,60)) { return 'UNKNOWN' }
    $Text=Remove-AuditUrlText $Text $Url
    $p=Get-AuditTlsPatterns
    if ($Text -match $p.NotRelated) { return 'UNKNOWN' }
    if ($Text -match $p.Reject) { return 'REJECT' }
    return 'UNKNOWN'
}

function Get-AuditGitVerdict {
    [CmdletBinding()]
    param([int]$ExitCode, [AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$Url='')
    # Targets are not Git repositories: a completed TLS handshake ends in an HTTP-level error.
    if ($ExitCode -eq 0) { return 'ACCEPT' }
    $Text=Remove-AuditUrlText $Text $Url
    $p=Get-AuditTlsPatterns
    if ($Text -match $p.NotRelated) { return 'UNKNOWN' }
    # REJECT only for a transport failure ("unable to access ...: <TLS diagnostic>").
    if ($Text -match 'unable to access' -and $Text -match $p.Reject) { return 'REJECT' }
    if ($Text -match $p.Reject) { return 'UNKNOWN' }
    # "<url>/info/refs not valid: is this a git repository?" (Git 2.40): the server answered the smart-HTTP request.
    if ($Text -match '(<url>|<host>)/?info/refs not valid: is this a git repository\?') { return 'ACCEPT' }
    if ($Text -match 'not found|\b404\b|\b403\b|not a git repository|unexpected disconnect') { return 'ACCEPT' }
    return 'UNKNOWN'
}

function Get-AuditSvnVerdict {
    [CmdletBinding()]
    param([int]$ExitCode, [AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$Url='')
    # Targets are not repositories: a completed TLS handshake ends in a DAV/HTTP-level error.
    # Run svn with --non-interactive and a throwaway --config-dir so no trust decision is stored.
    $Text=Remove-AuditUrlText $Text $Url
    # svn may follow a redirect ("Redirecting to URL ..."): any later answer or failure then belongs to another host.
    if ($Text -match 'Redirecting to URL|moved permanently|moved temporarily|E175011|E175012') { return 'UNKNOWN' }
    if ($ExitCode -eq 0) { return 'ACCEPT' }
    if ($Text -match 'E230001') {
        # "verification failed: <reason>[, <reason>...]"; REJECT only when the issuer is the sole reason.
        $m=[regex]::Match($Text,'E230001: Server SSL certificate verification failed: ([^\r\n]*)')
        if (-not $m.Success) { return 'UNKNOWN' }
        $reasons=@($m.Groups[1].Value.Trim() -split ',\s*' | Where-Object { $_ })
        if ($reasons.Count -gt 0 -and @($reasons | Where-Object { $_ -ne 'issuer is not trusted' }).Count -eq 0) { return 'REJECT' }
        return 'UNKNOWN'
    }
    # E175003 (no DAV, names the server: must be the target) / E175015 (OPTIONS not allowed) are answers to the OPTIONS
    # request sent inside the TLS tunnel. Authentication errors and other HTTP statuses can come from a proxy: UNKNOWN.
    if ($Text -match "E175003: The server at '(<url>|<host>)") { return 'ACCEPT' }
    if ($Text -match 'E175015') { return 'ACCEPT' }
    return 'UNKNOWN'
}

function Get-AuditPipVerdict {
    # Output of "pip download -vvv --only-binary=:all: --index-url <target> <random name>"; nothing is built or installed.
    # pip >= 24.2 verifies through truststore, which reports Windows' reason as localized FormatMessage text. The caller
    # passes those texts, produced by the same Python (ctypes.FormatError) for known error codes, so they match exactly.
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$Url='',
          [string[]]$RejectReasons=@(), [string[]]$UnrelatedReasons=@())
    # Only lines about the target count: an extra-index-url from pip's configuration is contacted too.
    $lines=@((Remove-AuditUrlText $Text $Url) -split "`r?`n" | Where-Object { $_ -match '<url>|<host>' })
    # urllib3 debug line ('https://<host>:443 "GET /x/ HTTP/1.1" 404 ...'): a response arrived, so the handshake completed.
    # ("https://<host>" is itself the URL without its trailing slash, so it becomes "<url>".)
    if (@($lines | Where-Object { $_ -match '(<host>|<url>):\d+ "GET [^"]*" \d{3}\b' }).Count) { return 'ACCEPT' }
    $failed=@($lines | Where-Object { $_ -match 'problem confirming the ssl certificate' })
    if ($failed.Count -eq 0) { return 'UNKNOWN' }
    $Text=$failed -join "`n"
    $p=Get-AuditTlsPatterns
    if ($Text -match $p.NotRelated) { return 'UNKNOWN' }
    foreach ($r in $UnrelatedReasons) { if ($r -and $Text.Contains($r)) { return 'UNKNOWN' } }
    if ($Text -match $p.Reject) { return 'REJECT' }
    foreach ($r in $RejectReasons) { if ($r -and $Text.Contains($r)) { return 'REJECT' } }
    return 'UNKNOWN'
}

function Get-AuditUvVerdict {
    # Output of "uv -v pip install --dry-run --no-deps --only-binary :all: --index-url <target> <random name>".
    # Sample output (uv 0.12.x):
    #   request sent:     DEBUG Sending fresh GET request for: <url><name>/
    #   target answered:  error: Unsupported `Content-Type` "text/plain" for <url>.... Expected JSON or HTML.
    #   control (404):    No solution found ... was not found in the package registry
    #   rejected:         Failed to fetch: `<url>...` / Caused by: error sending request for url (<url>...)
    #                     / Caused by: invalid peer certificate: UnknownIssuer (or Revoked with UV_NATIVE_TLS,
    #                     or Other(OtherError(CertDistrusted)) with uv 0.13.5)
    [CmdletBinding()]
    param([int]$ExitCode, [AllowEmptyString()][string]$Text, [AllowEmptyString()][string]$Url='')
    # Any other host in the diagnostics (a redirect target, an extra index) makes the failing peer uncertain.
    # Compare hosts exactly before masking: a text replacement would turn "https://t.example.evil/" into "<url>.evil/".
    $target=$null; [void][Uri]::TryCreate($Url,[UriKind]::Absolute,[ref]$target)
    $otherUrl=$false
    # DEBUG lines are ignored except the ones that record a request ("Sending fresh GET request for:", and in older uv
    # "No cache entry for:"): a request to another index makes a generic "not found" ambiguous.
    foreach ($line in @($Text -split "`r?`n" | Where-Object { $_ -notmatch '^\s*DEBUG ' -or $_ -match 'GET request for:|No cache entry for:' })) {
        foreach ($m in [regex]::Matches($line,'https?://[^\s`''"()<>]+')) {
            $u=$null
            if (-not $target -or -not [Uri]::TryCreate($m.Value,[UriKind]::Absolute,[ref]$u) -or
                $u.Host -ne $target.Host -or $u.Port -ne $target.Port -or $u.Scheme -ne $target.Scheme) { $otherUrl=$true }
        }
    }
    $Text=Remove-AuditUrlText $Text $Url
    $failed=($Text -match 'Failed to fetch|invalid peer certificate|error sending request')
    if ($failed) {
        if ($otherUrl) { return 'UNKNOWN' }
        # uv 0.11.x wraps the summary: "Failed to fetch:" / "error sending request for url" end the line and the URL follows
        # on the next one after a box-drawing bar (U+2502), e.g. "  |   `https://...`". Allow whitespace and that bar in between.
        # uv 0.12.22 on Linux prints it without backticks: "Failed to fetch: https://...".
        if ($Text -notmatch 'Failed to fetch:[\s\u2502]*`?(<url>|<host>)' -or $Text -notmatch 'error sending request for url[\s\u2502]*\((<url>|<host>)') { return 'UNKNOWN' }
        # uv 0.13.5 (without UV_NATIVE_TLS) rejects with its own root list: "Other(OtherError(CertDistrusted))".
        # Rewrite only that exact text (case-sensitive, followed by whitespace or the end, like sed in verify_wsl.sh); any other
        # Other(...) (even Other(OtherError(UnknownIssuer))) stays "Other" and so UNKNOWN.
        $Text=$Text -creplace 'invalid peer certificate: Other\(OtherError\(CertDistrusted\)\)(?=\s|$)','invalid peer certificate: CertDistrusted'
        $reasons=@([regex]::Matches($Text,'invalid peer certificate: ([A-Za-z]+)') | ForEach-Object { $_.Groups[1].Value })
        if ($reasons.Count -gt 0 -and @($reasons | Where-Object { $_ -notin @('UnknownIssuer','Revoked','CertDistrusted') }).Count -eq 0) { return 'REJECT' }
        return 'UNKNOWN'
    }
    # ACCEPT needs evidence that the target itself was asked (no-index or other settings may skip it) and answered.
    if ($otherUrl) { return 'UNKNOWN' }
    # The answer names the target URL, so it is evidence on its own (uv 0.7.14 / 0.9.17 do not log
    # "Sending fresh GET request").
    # uv 0.7.14 / 0.9.17 print "for <url>...", uv 0.12.22 on Linux prints "for `<url>...`".
    if ($Text -match 'Unsupported `Content-Type` "[^"]*" for `?(<url>|<host>)') { return 'ACCEPT' }
    # "not found in the package registry" does not name the index, so it needs "Sending fresh/revalidation GET request
    # for: <target>" (uv 0.12.x). Older uv only logs "No cache entry for:" before the request, which is not evidence that
    # the target answered (another index could have), so that case stays UNKNOWN.
    if ($Text -notmatch 'Sending (fresh|revalidation) GET request for: (<url>|<host>)') { return 'UNKNOWN' }
    if ($Text -match 'was not found in the package registry') { return 'ACCEPT' }
    return 'UNKNOWN'
}

function Get-AuditJavaInfo {
    # Version of a java.exe without running it: <home>\release (JDK 7+), else the file version (Java 6).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$JavaExe)
    $home_=Split-Path -Parent (Split-Path -Parent $JavaExe)
    $version=''; $source=''
    $release=Join-Path $home_ 'release'
    # Cloud-only placeholders are not opened (reading one starts a download); the version then stays unknown.
    if (Test-Path -LiteralPath $release -PathType Leaf) {
        if (Test-AuditCloudOnly -Item (Get-Item -LiteralPath $release)) { $source='cloud-only' }
        else {
            $m=[regex]::Match([IO.File]::ReadAllText($release),'(?m)^JAVA_VERSION="([^"]+)"')
            if ($m.Success) { $version=$m.Groups[1].Value; $source='release' }
        }
    }
    if (-not $version -and $source -ne 'cloud-only') {
        $exeItem=Get-Item -LiteralPath $JavaExe -ErrorAction SilentlyContinue
        if ($exeItem -and (Test-AuditCloudOnly -Item $exeItem)) { $source='cloud-only' }
        elseif ($exeItem) { $fv=$exeItem.VersionInfo.ProductVersion; if ($fv) { $version=[string]$fv; $source='file' } }
    }
    $major=$null
    $mm=[regex]::Match($version,'^(\d+)(?:\.(\d+))?')
    if ($mm.Success) {
        $major=[int]$mm.Groups[1].Value
        # "1.8.0_x" (release) means 8; file versions of Java 6/7 are "6.0.x" / "7.0.x".
        if ($major -eq 1 -and $mm.Groups[2].Success) { $major=[int]$mm.Groups[2].Value }
    }
    $cacerts=Join-Path $home_ 'lib\security\cacerts'
    [pscustomobject]@{ Java=$JavaExe; Home=$home_; Version=$version; VersionSource=$source; Major=$major
        Cacerts=$(if (Test-Path -LiteralPath $cacerts -PathType Leaf) { $cacerts } else { '' }) }
}

function ConvertFrom-AuditUvPythonList {
    # Paths from "uv python list --output-format json". Windows PowerShell 5.1's ConvertFrom-Json emits a
    # JSON array as one object; without unrolling, ".path" became all paths joined into one string.
    param([AllowEmptyString()][string]$Json)
    if (-not $Json -or -not $Json.Trim()) { return @() }
    @($Json | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $_ -and $_.path } | ForEach-Object { [string]$_.path })
}

function Get-AuditWindowsPythonCandidates {
    # Distribution Pythons: py launcher (PEP 514 registry, includes third-party such as Astral),
    # PATH (WindowsApps aliases excluded: a bare alias may only open the Store),
    # Microsoft Store packages (real per-package alias), and uv-managed Pythons.
    [CmdletBinding()]
    param()
    $list=[Collections.Generic.List[string]]::new()
    $py=Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($py) {
        try {
            $r=Invoke-AuditNativeProcess -FilePath $py.Source -ArgumentList @('--list-paths') -TimeoutMs 30000
            if ($r.ExitCode -ne 0) { Write-Warning "py --list-paths exit=$($r.ExitCode) (candidates may be incomplete)" }
            foreach ($line in ($r.StdOut -split "`r?`n")) {
                if ($line -match '([A-Za-z]:\\.+?pythonw?\.exe)') { $list.Add($Matches[1]) }
            }
        } catch { Write-Warning "py --list-paths failed: $($_.Exception.Message) (candidates may be incomplete)" }
    }
    foreach ($cmd in @(Get-Command python.exe -CommandType Application -All -ErrorAction SilentlyContinue)) {
        if ($cmd.Source -notmatch '\\WindowsApps\\') { $list.Add($cmd.Source) }
    }
    foreach ($pkg in @(Get-AppxPackage -Name 'PythonSoftwareFoundation.Python.*' -ErrorAction SilentlyContinue)) {
        $alias=Join-Path $env:LOCALAPPDATA ('Microsoft\WindowsApps\' + $pkg.PackageFamilyName + '\python.exe')
        if (Test-Path -LiteralPath $alias) { $list.Add($alias) }
    }
    $uv=Get-Command uv.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($uv) {
        try {
            $r=Invoke-AuditNativeProcess -FilePath $uv.Source -ArgumentList @('python','list','--only-installed','--output-format','json') -TimeoutMs 30000 -Encoding ([Text.UTF8Encoding]::new($false))
            if ($r.ExitCode -ne 0) { Write-Warning "uv python list exit=$($r.ExitCode) (candidates may be incomplete)" }
            foreach ($p in @(ConvertFrom-AuditUvPythonList $r.StdOut)) { $list.Add($p) }
        } catch { Write-Warning "uv python list failed: $($_.Exception.Message) (candidates may be incomplete)" }
    }
    @($list | Sort-Object -Unique)
}

function Get-AuditEmbeddedVersions {
    # Runtime version tokens embedded in a large executable: Electron's user-agent token "Electron/x.y.z"
    # and Bun's "Bun vx.y.z" (Claude Code native builds and other `bun build --compile` binaries).
    # The file is scanned in chunks (main executables are 150-300 MB) with an overlap so a token
    # crossing a chunk boundary is still found. Returns @{ Electron=@(...); Bun=@(...) }.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path, [int]$ChunkBytes=16MB)
    # The version must be followed by a non-version character: a token cut at the end of a chunk
    # ("Electron/42.11.1|6") is not matched there and is found complete in the next (overlapping) read.
    # A pre-release or build suffix ("-beta.1", "-canary", "+abc") is kept, so it is never compared as the release.
    # The whole token up to the first character that cannot belong to a version is kept ("1.4.4rc1", "1.4.4.5",
    # "-beta.1", "+abc"), so the strict comparison sees exactly what the binary says.
    $pattern=[regex]'(?:Electron/(?<e>\d+\.\d+\.\d+[0-9A-Za-z.\-+]*)|Bun v(?<b>\d+\.\d+\.\d+[0-9A-Za-z.\-+]*))(?=[^\dA-Za-z.\-+])'
    $overlap=64
    $electron=[Collections.Generic.HashSet[string]]::new()
    $bun=[Collections.Generic.HashSet[string]]::new()
    $stream=[IO.File]::Open($Path,'Open','Read','ReadWrite')
    try {
        $buffer=New-Object byte[] ($ChunkBytes + $overlap)
        $carry=0
        while (($read=$stream.Read($buffer,$carry,$ChunkBytes)) -gt 0) {
            $length=$carry + $read
            $text=[Text.Encoding]::ASCII.GetString($buffer,0,$length)
            foreach ($m in $pattern.Matches($text)) {
                if ($m.Groups['e'].Success) { [void]$electron.Add($m.Groups['e'].Value) } else { [void]$bun.Add($m.Groups['b'].Value) }
            }
            $carry=[Math]::Min($overlap,$length)
            [Array]::Copy($buffer,$length - $carry,$buffer,0,$carry)
        }
    } finally { $stream.Dispose() }
    @{ Electron=@($electron | Sort-Object); Bun=@($bun | Sort-Object) }
}

function Get-AuditElectronVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path, [int]$ChunkBytes=16MB)
    @((Get-AuditEmbeddedVersions -Path $Path -ChunkBytes $ChunkBytes).Electron)
}

function Find-AuditElectronApps {
    # Large executables under the given roots that embed an Electron or Bun version (one read per file).
    # Links and cloud placeholders are not followed (Get-AuditFilesNoLinks); what was not explored goes to Errors.
    # A cloud-only file is never opened (reading it would download it): a cloud placeholder is recorded in Errors as
    # "cloud-only, not read", and a file that only has the Offline / Recall attributes is returned with that ReadError.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string[]]$Root, [int]$Depth=3, [long]$MinBytes=60MB, [Collections.Generic.List[string]]$Errors)
    $exes=foreach ($r in @($Root | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique)) {
        Get-AuditFilesNoLinks -Root $r -Filter '*.exe' -Errors $Errors -MaxDepth $Depth | Where-Object { $_.Length -ge $MinBytes }
    }
    foreach ($exe in @($exes | Sort-Object FullName -Unique)) {
        $readError=''
        if (Test-AuditCloudOnly -Item $exe) {
            [pscustomobject]@{ Path=$exe.FullName; FileVersion=''; Written=$exe.LastWriteTime.ToString('s'); Electron=''; Bun=''; ReadError='cloud-only, not read' }
            continue
        }
        try { $v=Get-AuditEmbeddedVersions -Path $exe.FullName } catch { $v=@{ Electron=@(); Bun=@() }; $readError=$_.Exception.Message }
        if ($readError -or $v.Electron.Count -gt 0 -or $v.Bun.Count -gt 0) {
            [pscustomobject]@{ Path=$exe.FullName; FileVersion=$exe.VersionInfo.ProductVersion; Written=$exe.LastWriteTime.ToString('s');
                               Electron=($v.Electron -join ','); Bun=($v.Bun -join ','); ReadError=$readError }
        }
    }
}

function Test-AuditCloudOnly {
    # A cloud-only placeholder (OneDrive Files On-Demand and similar): opening or reading it downloads the file.
    # Offline (0x1000), RecallOnOpen (0x40000), RecallOnDataAccess (0x400000). Checking the attributes does not download.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][IO.FileSystemInfo]$Item)
    ([long]$Item.Attributes -band 0x441000) -ne 0
}

function Get-AuditReparseTag {
    # Reparse tag of a file or folder, read with FindFirstFileW (WIN32_FIND_DATA.dwReserved0). The file is not
    # opened, so a cloud placeholder is not downloaded. Returns 0 when the item has no reparse point.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not ('EmudhraAuditV1.Reparse' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace EmudhraAuditV1 {
    public static class Reparse {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct FindData {
            // FILETIME is two DWORDs (4-byte aligned): a long here would add padding and shift dwReserved0.
            public uint Attributes; public uint CreatedLow; public uint CreatedHigh; public uint AccessedLow; public uint AccessedHigh;
            public uint WrittenLow; public uint WrittenHigh;
            public uint SizeHigh; public uint SizeLow; public uint Reserved0; public uint Reserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Name;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AltName;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr FindFirstFileW(string name, out FindData data);
        [DllImport("kernel32.dll")]
        static extern bool FindClose(IntPtr handle);
        public static uint GetTag(string path) {
            FindData d;
            IntPtr h = FindFirstFileW(path, out d);
            if (h == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            FindClose(h);
            return (d.Attributes & 0x400) != 0 ? d.Reserved0 : 0;
        }
    }
}
'@
    }
    $full=[IO.Path]::GetFullPath($Path)
    if ($full -match '^[A-Za-z]:\\') { $full='\\?\' + $full }   # long paths (deep site-packages)
    [EmudhraAuditV1.Reparse]::GetTag($full)
}

function Test-AuditLocalCloudFile {
    # A file that carries only a cloud-files reparse tag (IO_REPARSE_TAG_CLOUD, CLOUD_1..F = 0x9000?01A) and whose
    # data is on the disk (no Offline / RecallOnOpen / RecallOnDataAccess). Reading it does not download anything.
    # Folders removed from cloud sync (e.g. OneDrive) can keep this tag on every file (e.g. 0x9000201A).
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][uint32]$Tag, [Parameter(Mandatory=$true)][long]$Attributes)
    # Hex literals above 0x7FFFFFFF are negative Int32 in PowerShell, so the constants are built as Int64.
    $mask=[Convert]::ToInt64('FFFF0FFF',16); $cloud=[Convert]::ToInt64('9000001A',16)
    ((([long]$Tag) -band $mask) -eq $cloud) -and (($Attributes -band 0x441000) -eq 0)
}

function Get-AuditReadDecision {
    # Whether a file may be read, from its attributes and reparse tag only (nothing is opened): '' = read it,
    # 'cloud-only' = a placeholder whose data is not on the disk (reading would download it), 'link' = another reparse
    # point (junction, symbolic link, ...). A file that only carries a cloud-files tag with local data (a folder that
    # was removed from cloud sync) is read, as Get-AuditBrotliLibRow already does.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][long]$Attributes, [uint32]$Tag=0)
    if (($Attributes -band 0x441000) -ne 0) { return 'cloud-only' }
    if (($Attributes -band [long][IO.FileAttributes]::ReparsePoint) -eq 0) { return '' }
    if (Test-AuditLocalCloudFile -Tag $Tag -Attributes $Attributes) { return '' }
    'link'
}

function Get-AuditReadSkipReason {
    # Get-AuditReadDecision for a file on disk: reads the reparse tag only when the file is a reparse point.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][IO.FileSystemInfo]$Item)
    $a=[long]$Item.Attributes
    $tag = if (($a -band [long][IO.FileAttributes]::ReparsePoint) -ne 0 -and ($a -band 0x441000) -eq 0) { Get-AuditReparseTag -Path $Item.FullName } else { [uint32]0 }
    Get-AuditReadDecision -Attributes $a -Tag $tag
}

function Get-AuditFilesNoLinks {
    # Files under Root matching Filter, without following junctions / symbolic links (Windows PowerShell 5.1's
    # Get-ChildItem -Recurse follows directory links). A link Root returns nothing. Folders that cannot be listed
    # and skipped links are added to Errors (a List[string]) so the caller can report them as not explored.
    # (An empty list is falsy in PowerShell, so the test is against $null.)
    # PruneDirectoryName: folder names (any level, case-insensitive) that are not entered at all; they are excluded
    # on purpose, so they are not added to Errors. MaxDepth works like Get-ChildItem -Depth (0 = Root's own entries
    # only; -1 = unlimited).
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Root, [string]$Filter='*', [Collections.Generic.List[string]]$Errors,
          [string[]]$PruneDirectoryName=@(), [int]$MaxDepth=-1)
    $rootItem=Get-Item -LiteralPath $Root -ErrorAction SilentlyContinue
    if (-not $rootItem) { if ($null -ne $Errors) { $Errors.Add("$Root : not found") }; return }
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { if ($null -ne $Errors) { $Errors.Add("$Root : link, not followed") }; return }
    $prune=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @($PruneDirectoryName)) { if ($n) { [void]$prune.Add($n) } }
    $stack=[Collections.Generic.Stack[object]]::new(); $stack.Push(@($rootItem.FullName, 0))
    while ($stack.Count) {
        $top=$stack.Pop(); $d=$top[0]; $level=$top[1]
        try { $entries=@([IO.DirectoryInfo]::new($d).GetFileSystemInfos()) } catch { if ($null -ne $Errors) { $Errors.Add("$d : $($_.Exception.Message)") }; continue }
        foreach ($e in $entries) {
            $isDir=$e -is [IO.DirectoryInfo]
            # Pruned folders are excluded on purpose, even when they are links, so they are checked first.
            if ($isDir -and $prune.Contains($e.Name)) { continue }
            # Files that do not match the filter are never returned, so a reparse point on them does not matter.
            if (-not $isDir -and $e.Name -notlike $Filter) { continue }
            if ($e.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                # Folders with a reparse point (junctions, symbolic links, cloud placeholders) are never entered.
                # A matching file is returned only when it carries just a cloud-files tag and its data is local
                # (Test-AuditLocalCloudFile). A cloud-files tag without local data is recorded as cloud-only (never
                # returned, so no caller can open it); symbolic links and other reparse points are recorded as links
                # (a file symlink would make the caller read a file outside Root).
                $note='link, not followed'
                if (-not $isDir) {
                    try {
                        $tag=Get-AuditReparseTag -Path $e.FullName
                        if (Test-AuditLocalCloudFile -Tag $tag -Attributes ([long]$e.Attributes)) { $e; continue }
                        if (Test-AuditLocalCloudFile -Tag $tag -Attributes 0) { $note='cloud-only, not read' }
                    } catch { $note="reparse tag not readable ($($_.Exception.Message)), not read" }
                }
                if ($null -ne $Errors) { $Errors.Add("$($e.FullName) : $note") }
                continue
            }
            if ($isDir) {
                if ($MaxDepth -lt 0 -or $level -lt $MaxDepth) { $stack.Push(@($e.FullName, ($level + 1))) }
            }
            else { $e }
        }
    }
}

function Test-AuditPyInstallerOnefile {
    # A PyInstaller one-file executable carries its archive (Python DLL, extensions, data such as cacert.pem)
    # inside the exe and unpacks it to a temp folder only when started, so a file scan cannot see its contents.
    # The archive ends with the cookie magic "MEI\x0C\x0B\x0A\x0B\x0E"; an Authenticode signature may follow it,
    # so the last $TailBytes are searched.
    [CmdletBinding()]
    # Note: a one-folder build's launcher exe carries a small archive with the same cookie; the caller tells them apart
    # (a one-folder build has python3*.dll next to the exe or in _internal).
    param([Parameter(Mandatory=$true)][string]$Path, [int]$TailBytes=256KB)
    $magic=[byte[]](0x4D,0x45,0x49,0x0C,0x0B,0x0A,0x0B,0x0E)
    $stream=[IO.File]::Open($Path,'Open','Read','ReadWrite')
    try {
        $n=[int][Math]::Min([long]$TailBytes,$stream.Length)
        [void]$stream.Seek(-$n,'End')
        $buf=New-Object byte[] $n
        $read=0; while ($read -lt $n) { $r=$stream.Read($buf,$read,$n - $read); if ($r -le 0) { break }; $read+=$r }
    } finally { $stream.Dispose() }
    for ($i=0; $i -le $read - $magic.Length; $i++) {
        if ($buf[$i] -ne 0x4D) { continue }
        $ok=$true; for ($k=1; $k -lt $magic.Length; $k++) { if ($buf[$i+$k] -ne $magic[$k]) { $ok=$false; break } }
        if ($ok) { return $true }
    }
    return $false
}

function Compare-AuditFixedVersion {
    # Compare a version with the fixed releases of each maintained line.
    #   -LineParts 1: a line is the major version (Node 22/24/26). 2: major.minor (libbrotli 1.0/1.1/1.2).
    #   -LineParts 0: a single sequence (Pillow 13.0.0, Bun 1.4.4, certifi 2026.10.19): below any fixed one = VULNERABLE.
    # Same line: >= fixed is FIXED, below is VULNERABLE. A line without a fix but older than a fixed line
    # (an end-of-life line) is VULNERABLE. Newer than every fixed line, or unparsable: UNKNOWN.
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Version, [Parameter(Mandatory=$true)][string[]]$Fixed, [ValidateRange(0,2)][int]$LineParts=1)
    # The whole string must be a plain release ("v" prefix allowed, 1-4 numeric parts). Pre-releases and
    # other suffixes (13.0.0rc1, 1.4.4-canary, 24.22.1-rc.1), extra parts and overflowing numbers are UNKNOWN:
    # a pre-release of the fixed version must not count as the fixed release.
    $m=[regex]::Match([string]$Version,'^\s*v?(\d+(?:\.\d+){0,3})\s*$')
    if (-not $m.Success) { return 'UNKNOWN' }
    $parts=@($m.Groups[1].Value -split '\.')
    foreach ($x in $parts) { $n=0; if (-not [int]::TryParse($x,[ref]$n)) { return 'UNKNOWN' } }
    # Pad to four parts: [version] treats a missing part as -1, so 13.0 would sort below 13.0.0.
    while ($parts.Count -lt 4) { $parts+='0' }
    $v=[version]($parts -join '.')
    $fixedVersions=@($Fixed | ForEach-Object { $p=@($_ -split '\.'); while ($p.Count -lt 4) { $p+='0' }; [version]($p -join '.') })
    if ($LineParts -eq 0) {
        $lowest=($fixedVersions | Sort-Object | Select-Object -First 1)
        if ($v -ge $lowest) { return 'FIXED' } else { return 'VULNERABLE' }
    }
    $key={ param($x) if ($LineParts -eq 1) { "$($x.Major)" } else { "$($x.Major).$($x.Minor)" } }
    foreach ($f in $fixedVersions) {
        if ((& $key $f) -eq (& $key $v)) { if ($v -ge $f) { return 'FIXED' } else { return 'VULNERABLE' } }
    }
    if (@($fixedVersions | Where-Object { $_ -gt $v }).Count -gt 0) { return 'VULNERABLE' }
    return 'UNKNOWN'
}

function Invoke-AuditPythonSet {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string[]]$PythonPaths,
          [Parameter(Mandatory=$true)][string]$ProbeScript,
          [string]$Control='https://www.google.com/',
          [string[]]$Targets=@('https://dv-g3b-emudhra.we-have-a-problem.com/','https://dv-g3b-aaa-emudhra.we-have-a-problem.com/'),
          [switch]$KnownTlsInspection)
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($pythonPath in @($PythonPaths | Sort-Object -Unique)) {
        foreach ($url in @($Control) + $Targets) {
            try {
                $data=@(Invoke-AuditPythonProcess -Python $pythonPath -ProbeScript $ProbeScript -Url $url)
            } catch {
                $data=@(foreach ($route in @('stdlib-ssl','certifi','requests')) {
                    [pscustomobject]@{ route=$route; verdict='UNKNOWN'; detail='Process failed or output invalid.' }
                })
            }
            foreach ($item in $data) {
                $verdict=$item.verdict
                if ($KnownTlsInspection) { $verdict='UNKNOWN' }
                $rows.Add([pscustomobject]@{ Tool="py:$pythonPath/$($item.route)";
                    Target=$url; Verdict=$verdict; Detail=$item.detail })
            }
        }
    }
    [pscustomobject]@{
        Rows=@($rows.ToArray())
        Summary=@(Get-AuditSummary -Rows $rows.ToArray() -Control $Control -Targets $Targets)
    }
}

function Get-AuditPythonPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$InventoryCsv,
          [string[]]$DistributionPython=@(), [string[]]$EmbeddedPython=@(),
          [string[]]$CondaPrefixes=@(), [string[]]$PipxPython=@())
    $paths=[Collections.Generic.List[string]]::new()
    foreach ($p in @($DistributionPython) + @($EmbeddedPython) + @($PipxPython)) {
        if (-not [string]::IsNullOrWhiteSpace($p)) { $paths.Add($p) }
    }
    foreach ($row in @(Import-Csv -LiteralPath $InventoryCsv -Encoding UTF8 -ErrorAction Stop)) {
        # Retain failed/missing executables as UNKNOWN rather than silently dropping them.
        if ($row.kind -eq 'windows' -and $row.python) { $paths.Add($row.python) }
        # The venv's base interpreter is a separate Python (e.g. an app-bundled one not known to py.exe).
        if ($row.kind -eq 'windows' -and $row.base_python) {
            $base=Join-Path $row.base_python 'python.exe'
            if (Test-Path -LiteralPath $base) { $paths.Add($base) }
        }
    }
    foreach ($prefix in $CondaPrefixes) {
        if (-not [string]::IsNullOrWhiteSpace($prefix)) { $paths.Add((Join-Path $prefix 'python.exe')) }
    }
    @($paths | ForEach-Object { [IO.Path]::GetFullPath($_) } | Sort-Object -Unique)
}

function Export-AuditLinuxVenvPaths {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$InventoryCsv,
          [Parameter(Mandatory=$true)][string]$OutputPath)
    # Call only AFTER inventory completion. Do not race the inventory writer.
    $paths=@(Import-Csv -LiteralPath $InventoryCsv -Encoding UTF8 -ErrorAction Stop |
        Where-Object { $_.kind -eq 'linux' } | ForEach-Object { $_.venv } | Sort-Object -Unique)
    $text=''
    if ($paths.Count -gt 0) { $text=($paths -join "`n") + "`n" }
    Write-AuditUtf8 -Path $OutputPath -Text $text
}

function Get-AuditGitTlsSettings {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$GitExe)
    # Query only TLS keys, never enumerate extraHeader or credential helpers.
    $pattern='^http(\..*)?\.(sslbackend|sslcainfo|sslcapath|sslverify)$'
    $savedPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $captured=@(& $GitExe config --show-origin --get-regexp $pattern 2>&1)
        $code=$LASTEXITCODE
    } finally { $ErrorActionPreference=$savedPreference }
    if ($code -eq 1) { return } # No matching configuration.
    if ($code -ne 0) { throw "Git TLS config query failed (exit=$code). Raw values withheld." }
    foreach ($line in $captured) {
        # Userinfo can occur in a URL-scoped key as well as in a value.
        ([string]$line) -replace '://[^/@\s]+@','://<redacted>@'
    }
}

function Get-AuditBrotliLibKind {
    # Classify a file by its NAME only (nothing is opened). Used by the 3.2 walk to collect Brotli-carrying libraries:
    #   brotli-lib    libbrotlidec*.dll, brotlidec.dll, CORE_RL_brotli_.dll (ImageMagick)
    #   cef           libcef.dll (Chromium Embedded Framework)
    #   qtwebengine   Qt5WebEngineCore.dll / Qt6WebEngineCore.dll (Chromium inside Qt)
    #   dotnet-native System.IO.Compression.Native.dll of a self-contained .NET app (it holds the native Brotli).
    #                 The copy inside a shared runtime (...\shared\Microsoft.NETCore.App\<ver>\) is judged by dotnet.exe
    #                 (6.4 step 8), so it returns '' here.
    # Returns '' when the name is not one of these.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $name=[IO.Path]::GetFileName($Path)
    if ($name -imatch '^libbrotlidec.*\.dll$' -or $name -ieq 'brotlidec.dll' -or $name -ieq 'CORE_RL_brotli_.dll') { return 'brotli-lib' }
    if ($name -ieq 'libcef.dll') { return 'cef' }
    if ($name -imatch '^Qt[56]WebEngineCore\.dll$') { return 'qtwebengine' }
    if ($name -ieq 'System.IO.Compression.Native.dll') {
        if ($Path -imatch '[\\/]shared[\\/]Microsoft\.NETCore\.App[\\/][^\\/]+[\\/][^\\/]+$') { return '' }
        return 'dotnet-native'
    }
    ''
}

function Get-AuditBrotliLibRow {
    # One row of brotli-lib-found.csv. Reads only file metadata and the version resource; a cloud-only placeholder or a
    # link is never opened (Note says so). Nothing is loaded or executed.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $row=[ordered]@{ FullName=$Path; Kind=(Get-AuditBrotliLibKind -Path $Path); Length=''; LastWriteTime=''; FileVersion=''; ProductVersion='';
                     CompanyName=''; CloudOnly='False'; Note='' }
    try {
        $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $row.Length=[string]$item.Length; $row.LastWriteTime=$item.LastWriteTime.ToString('s')
        if (Test-AuditCloudOnly -Item $item) { $row.CloudOnly='True'; $row.Note='cloud-only, not read' }
        elseif ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            # Only a local cloud-files file (a folder that left OneDrive keeps the tag) is read; any other link is not followed.
            $tag=Get-AuditReparseTag -Path $Path
            if (-not (Test-AuditLocalCloudFile -Tag $tag -Attributes ([long]$item.Attributes))) { $row.Note='link, not read' }
        }
        if (-not $row.Note) {
            $vi=$item.VersionInfo
            $row.FileVersion=[string]$vi.FileVersion; $row.ProductVersion=[string]$vi.ProductVersion; $row.CompanyName=[string]$vi.CompanyName
        }
    } catch { $row.Note="not read: $($_.Exception.Message)" }
    [pscustomobject]$row
}

function Get-AuditBrotliKnownHashes {
    # SHA256 of libbrotlidec.dll builds that are identified by hash (6.4). Anything else is not guessed.
    #   FIXED       MSYS2 brotli 1.2.1-1 (what Replace-GitBrotli.ps1 installs)
    #   VULNERABLE  the MSYS2 brotli 1.2.0 that Git for Windows / PortableGit ship (up to 2.56.0.windows.3). Other MSYS2-based
    #               apps carry the same file (e.g. apps built on MSYS2 ucrt64), so the name does not say Git.
    [CmdletBinding()]
    param()
    @(
        [pscustomobject]@{ Sha256='dab7d47981ee887865d1f82dcbcc8fc4c7a43942278bb27877e168909e10d346'; Verdict='FIXED';      Version='1.2.1'; Name='MSYS2 brotli 1.2.1-1 mingw64' },
        [pscustomobject]@{ Sha256='c4c987a01597ddf969d93023f933f999a20f285588b0decb4deeb780c9e9cdf8'; Verdict='FIXED';      Version='1.2.1'; Name='MSYS2 brotli 1.2.1-1 ucrt64' },
        [pscustomobject]@{ Sha256='a142dc6cfa77cb907028aa9426f486f3d8de37855e8db2ae2894147908121881'; Verdict='VULNERABLE'; Version='1.2.0'; Name='MSYS2 brotli 1.2.0 mingw64 (as shipped by Git for Windows)' },
        [pscustomobject]@{ Sha256='e270b6e576594ee8ee6e33ccc54e34a54304616dd6225652e11e49d6f17ef896'; Verdict='VULNERABLE'; Version='1.2.0'; Name='MSYS2 brotli 1.2.0 ucrt64 (as shipped by Git for Windows)' }
    )
}

function Get-AuditGitRootOfFile {
    # If Path is a library of a Git for Windows tree, return its root; otherwise $null. A library sits in
    # <root>\{mingw64,ucrt64,mingw32}\bin or <root>\<prefix>\libexec\git-core, and the root is a Git when
    # <root>\cmd\git.exe, <root>\bin\git.exe or <root>\<prefix>\bin\git.exe exists (MinGit has the last one only).
    # Is32 is true for mingw32 (Replace-GitBrotli.ps1 has no 32-bit package).
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $dir=Split-Path -Parent $Path
    if (-not $dir) { return $null }
    $leaf=Split-Path -Leaf $dir
    if ($leaf -ieq 'git-core') {
        $lib=Split-Path -Parent $dir
        if (-not $lib -or (Split-Path -Leaf $lib) -ine 'libexec') { return $null }
        $prefixDir=Split-Path -Parent $lib
    } elseif ($leaf -ieq 'bin') { $prefixDir=Split-Path -Parent $dir }
    else { return $null }
    if (-not $prefixDir) { return $null }
    $prefix=Split-Path -Leaf $prefixDir
    if ($prefix -inotmatch '^(mingw64|ucrt64|mingw32)$') { return $null }
    $root=Split-Path -Parent $prefixDir
    if (-not $root) { return $null }
    foreach ($g in @((Join-Path $root 'cmd\git.exe'), (Join-Path $root 'bin\git.exe'), (Join-Path $prefixDir 'bin\git.exe'))) {
        if (Test-Path -LiteralPath $g -PathType Leaf) {
            return [pscustomobject]@{ Root=$root; Prefix=$prefix.ToLowerInvariant(); Is32=($prefix -ieq 'mingw32') }
        }
    }
    $null
}

function Test-AuditBrotliBackupPath {
    # Is this DLL one of the copies Replace-GitBrotli.ps1 moved aside? Only its exact layout counts, so a live DLL in a
    # folder that merely carries the name is not hidden:
    #   <Git root>\_emudhra_backup_brotli-<x.y.z>[-<yyyyMMdd>-<HHmmss>-<8 hex>]\[<prefix>_bin\ | <prefix>_libexec_git-core\]libbrotli{common,dec,enc}.dll
    # and <Git root>\cmd\git.exe exists (the backup sits directly in a Git for Windows / PortableGit tree).
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $m=[regex]::Match($Path, '^(?<root>.+)[\\/]_emudhra_backup_brotli-\d+\.\d+\.\d+(?:-\d{8}-\d{6}-[0-9a-f]{8})?[\\/](?:[A-Za-z0-9]+_(?:bin|libexec_git-core)[\\/])?libbrotli(?:common|dec|enc)\.dll$', 'IgnoreCase')
    if (-not $m.Success) { return $false }
    [IO.File]::Exists((Join-Path $m.Groups['root'].Value 'cmd\git.exe'))
}

function Get-AuditBrotliLibVerdict {
    # Verdict for one row of brotli-lib-found.csv (6.4). The caller hashes the file (Get-FileHash) for brotli-lib and
    # passes Sha256, or ReadError when it could not. Returns Verdict, Version, Reason (a code the runbook turns into
    # a note), Known (name of a known build), GitRoot / GitPrefix / GitIs32 (set for a brotli-lib inside a Git for Windows tree, whatever the verdict).
    #   brotli-lib    known hash -> FIXED / VULNERABLE; any other hash, a cloud-only file, a link or a read error -> UNKNOWN
    #   cef, qtwebengine  UNKNOWN (Chromium has announced no Brotli fix; the app must be updated)
    #   dotnet-native VULNERABLE (.NET has no fix, same as the dotnet-runtime rows)
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Row, [string]$Sha256='', [string]$ReadError='')
    $ver=@($Row.ProductVersion, $Row.FileVersion | Where-Object { $_ })[0]
    $r=[ordered]@{ Verdict='UNKNOWN'; Version=[string]$ver; Reason=''; Known=''; GitRoot=''; GitPrefix=''; GitIs32=$false }
    switch ([string]$Row.Kind) {
        'cef' { $r.Reason='chromium-embedded' }
        'qtwebengine' { $r.Reason='chromium-embedded' }
        'dotnet-native' {
            # .NET had no fix on 2026-10-24 (runbook section 4). Only a Microsoft-built DLL with a readable version counts as that .NET;
            # anything else (another company, unread, no version) is not assumed to be it. Re-check when .NET ships a fix.
            $r.Version=[string]$Row.FileVersion
            if ($Row.Note -or -not $Row.FileVersion) { $r.Reason='not-read'; break }
            if ([string]$Row.CompanyName -notmatch 'Microsoft') { $r.Reason='dotnet-not-microsoft'; break }
            $r.Verdict='VULNERABLE'; $r.Reason='dotnet-no-fix' }
        'brotli-lib' {
            # the owner is told from the path alone (existence checks only), whatever the verdict
            $g=Get-AuditGitRootOfFile -Path ([string]$Row.FullName)
            if ($g) { $r.GitRoot=$g.Root; $r.GitPrefix=$g.Prefix; $r.GitIs32=$g.Is32 }
            # a copy that Replace-GitBrotli.ps1 (or a per-machine script) moved aside: no program loads it; it is kept to roll back.
            # INFO, so neither the old 1.2.0 (VULNERABLE) nor a hard-linked 1.2.1 (FIXED) is counted; Known still names the build.
            if (Test-AuditBrotliBackupPath -Path ([string]$Row.FullName)) {
                $r.Verdict='INFO'; $r.Reason='backup'
                if ($Sha256) { $hit=@(Get-AuditBrotliKnownHashes | Where-Object { $_.Sha256 -eq $Sha256.ToLowerInvariant() }); if ($hit.Count -eq 1) { $r.Version=$hit[0].Version; $r.Known=$hit[0].Name } }
                break
            }
            if ($Row.CloudOnly -eq 'True') { $r.Reason='cloud-only'; break }
            if ($Row.Note) { $r.Reason='not-read'; break }
            if ($ReadError -or -not $Sha256) { $r.Reason='hash-error'; break }
            $hit=@(Get-AuditBrotliKnownHashes | Where-Object { $_.Sha256 -eq $Sha256.ToLowerInvariant() })
            if ($hit.Count -eq 1) { $r.Verdict=$hit[0].Verdict; $r.Version=$hit[0].Version; $r.Known=$hit[0].Name; $r.Reason='known-hash'; break }
            $r.Reason='unknown-hash'
        }
        default { $r.Reason='unexpected-kind' }
    }
    [pscustomobject]$r
}

function Get-AuditNeighborExeText {
    # Hints about which application owns a library: the exe files in its folder and in the parent folder with their
    # ProductVersion (at most 3 each; cloud-only files are not opened). Nothing is run. Returns '' when there are none.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $dir=Split-Path -Parent $Path
    $dirs=@($dir)
    if ($dir) { $dirs += Split-Path -Parent $dir }
    $parts=foreach ($d in @($dirs | Where-Object { $_ } | Select-Object -Unique)) {
        $exes=@(Get-ChildItem -LiteralPath $d -Filter '*.exe' -File -ErrorAction SilentlyContinue | Select-Object -First 3)
        foreach ($e in $exes) {
            # like Get-AuditBrotliLibRow: a link is not followed (only a local cloud-files file is read)
            $pv=if (Test-AuditCloudOnly -Item $e) { 'cloud-only' }
                elseif (($e.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                        -not (Test-AuditLocalCloudFile -Tag (Get-AuditReparseTag -Path $e.FullName) -Attributes ([long]$e.Attributes))) { 'link, not read' }
                else { [string]$e.VersionInfo.ProductVersion }
            "$($e.FullName) [$pv]"
        }
    }
    (@($parts) -join '; ')
}

# Supply-chain attacks of Aug-Oct 2026 that reach developer machines through CI and packages (v2.12.2):
#   LiteLLM 1.107.0 (2026-10-21): cook.pth / cook.py in site-packages, run on every Python start.
#   GhostAction-style workflows: secret-stealing workflow files and strings.
#   ChainDrop / tensorlake@0.5.144 (2026-10-08): npm preinstall worm that also plants .claude/settings.json and .vscode/tasks.json.
$script:AuditIocStrings = 'AKIA_CTX_START|c=monami|193\.32\.204\.199|45\.139\.104\.115|170\.39\.218\.2|oast\.fun'
$script:AuditIocWorkflowNames = @('security-audit.yml','github_actions_security.yml','security-check.yml')

function Get-AuditIocCandidateKind {
    # Classify a path by NAME and location only (nothing is opened). '' when it is not something the IOC check reads.
    #   sitepkg-ioc      cook.pth / cook.py directly in site-packages, or a litellm-1.107.0.dist-info folder
    #   workflow         *.yml / *.yaml in .github\workflows
    #   lockfile         package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, bun.lock
    #   vscode-tasks     .vscode\tasks.json
    #   claude-settings  .claude\settings.json / settings.local.json
    #   npm-tensorlake   node_modules\tensorlake\package.json
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    $p=$Path -replace '/','\'; $name=[IO.Path]::GetFileName($p.TrimEnd('\')); $parent=[IO.Path]::GetFileName([IO.Path]::GetDirectoryName($p.TrimEnd('\')))
    if ($parent -ieq 'site-packages' -and ($name -ieq 'cook.pth' -or $name -ieq 'cook.py' -or $name -ieq 'litellm-1.107.0.dist-info')) { return 'sitepkg-ioc' }
    if ($p -imatch '\\\.github\\workflows\\[^\\]+\.ya?ml$') { return 'workflow' }
    if ($name -imatch '^(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$') { return 'lockfile' }
    if ($p -imatch '\\\.vscode\\tasks\.json$') { return 'vscode-tasks' }
    if ($p -imatch '\\\.claude\\settings(\.local)?\.json$') { return 'claude-settings' }
    if ($p -imatch '\\node_modules\\tensorlake\\package\.json$') { return 'npm-tensorlake' }
    ''
}

function Test-AuditPinnedVersion {
    # Does a manifest or lockfile pin $Package at exactly $Version? The version must belong to that package's own entry:
    #   same line:   litellm==1.107.0, /tensorlake@0.5.144:, "tensorlake": ["tensorlake@0.5.144", ...]
    #   later line:  only a "version" field (package-lock "version": "x", yarn  version "x", uv.lock / poetry version = "x"),
    #                within 4 lines, stopping at a blank line, a '}' or a '[' (the end of that entry).
    # So "litellm==1.106.0" followed by "other==1.107.0" is not a match.
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text, [Parameter(Mandatory=$true)][string]$Package, [Parameter(Mandatory=$true)][string]$Version)
    $pkg=[regex]::Escape($Package); $ver=[regex]::Escape($Version); $lines=$Text -split "`r?`n"
    for ($i=0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch "(?i)(?<![A-Za-z0-9_-])$pkg(?![A-Za-z0-9_-])") { continue }
        # a range (>=, ^, ~, <, !=, *, ||) does not fix the version: only an exact pin on the same line counts
        $sm=[regex]::Match($lines[$i], "(?i)(?<![A-Za-z0-9_-])$pkg(?![A-Za-z0-9_-])([^,;}\r\n]{0,80}?)(?<![0-9.])$ver(?![0-9A-Za-z.+-])")
        if ($sm.Success -and $sm.Groups[1].Value -notmatch '[<>^~!*]|\|\|') { return $true }   # stop at , ; } (the next entry on the same line; a { right after the name opens its own entry)
        for ($j=$i+1; $j -le [Math]::Min($i+4, $lines.Count-1); $j++) {
            $l=$lines[$j]
            # stop at the end of the entry, or where a nested object starts (its versions belong to other packages)
            if ($l -match '^\s*$' -or $l -match '[{}]' -or $l -match '^\s*\[') { break }
            # the first version field is the package's own version: decide on it and stop
            $vm=[regex]::Match($l, '^\s*"?version"?\s*[:=]?\s*"?([^"\s,]+)"?\s*,?\s*$')
            if ($vm.Success) { if ($vm.Groups[1].Value -eq $Version) { return $true } else { break } }
        }
    }
    $false
}

function Get-AuditIocFinding {
    # Judge one candidate from its kind and (for files) its text. Returns $null when nothing is suspicious, otherwise
    # Level HIGH (matches a published indicator) or CHECK (worth a look: could be legitimate, e.g. a project's own
    # security-audit.yml or a VS Code task that runs when the folder opens). Detail never contains more than 160
    # characters of file content.
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path, [AllowEmptyString()][string]$Text='')
    $kind=Get-AuditIocCandidateKind -Path $Path
    if (-not $kind) { return $null }
    function New-Finding($Level, $What, $Detail) { [pscustomobject]@{ Level=$Level; Kind=$kind; FullName=$Path; What=$What; Detail="$Detail".Substring(0,[Math]::Min(160,"$Detail".Length)) } }
    $m=[regex]::Match($Text, $script:AuditIocStrings)
    # A lockfile may put the version on a later line (formatted package-lock.json, yarn.lock, uv.lock): look at the
    # name and the next few lines of each occurrence, up to the end of that entry.
    $pinned=Test-AuditPinnedVersion -Text $Text -Package 'tensorlake' -Version '0.5.144'
    switch ($kind) {
        'sitepkg-ioc' { return (New-Finding 'HIGH' 'LiteLLM 1.107.0 indicator in site-packages' ([IO.Path]::GetFileName($Path.TrimEnd('\','/')))) }
        'workflow' {
            if ($m.Success) { return (New-Finding 'HIGH' 'attacker string in a workflow' $m.Value) }
            # risky but not proof of theft (it may only pass the secrets to a step): CHECK
            if ($Text -match 'toJSON\(\s*secrets\s*\)') { return (New-Finding 'CHECK' 'workflow passes all secrets at once (toJSON(secrets)); check where they go' '') }
            if ($script:AuditIocWorkflowNames -contains ([IO.Path]::GetFileName($Path)).ToLowerInvariant()) { return (New-Finding 'CHECK' 'workflow file name used by GhostAction-style attacks (check who added it)' '') }
            return $null
        }
        'lockfile' {
            if ($Text -notmatch '(?i)tensorlake') { return $null }
            if ($pinned) { return (New-Finding 'HIGH' 'lockfile pins tensorlake 0.5.144 (ChainDrop worm)' '') }
            return (New-Finding 'CHECK' 'lockfile mentions tensorlake (check the version)' '')
        }
        'npm-tensorlake' {
            $v=[regex]::Match($Text, '"version"\s*:\s*"([^"]+)"').Groups[1].Value
            $level = if ($v -eq '0.5.144') { 'HIGH' } else { 'CHECK' }
            return (New-Finding $level 'tensorlake installed in node_modules' "version=$v")
        }
        'vscode-tasks' {
            if ($m.Success) { return (New-Finding 'HIGH' 'attacker string in .vscode\tasks.json' $m.Value) }
            if ($Text -match '"runOn"\s*:\s*"folderOpen"') { return (New-Finding 'CHECK' 'VS Code task runs when the folder opens (the worm plants these; check who added it)' '') }
            return $null
        }
        'claude-settings' {
            if ($m.Success) { return (New-Finding 'HIGH' 'attacker string in .claude settings' $m.Value) }
            if ($Text -match '(?i)tensorlake') { return (New-Finding 'CHECK' 'tensorlake mentioned in .claude settings (check who added it)' '') }
            return $null
        }
    }
    $null
}
