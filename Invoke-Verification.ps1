#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PythonListPath,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$KnownTlsInspection,
    [switch]$IncludeWindowsTrustProbe
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Test-Emudhra.Helpers.ps1')
$pythonPaths=@([IO.File]::ReadAllLines([IO.Path]::GetFullPath($PythonListPath),[Text.Encoding]::UTF8) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
if ($pythonPaths.Count -eq 0) { throw 'Python list is empty. Populate it from the COMPLETE inventory first.' }
foreach ($path in $pythonPaths) {
    if (-not [IO.Path]::IsPathRooted($path)) { throw 'Each Python path must be absolute.' }
}
$out=[IO.Path]::GetFullPath($OutputDirectory)
[void][IO.Directory]::CreateDirectory($out)
$pythonResult=Invoke-AuditPythonSet -PythonPaths $pythonPaths -ProbeScript (Join-Path $PSScriptRoot 'probe_python.py') -KnownTlsInspection:$KnownTlsInspection
Write-AuditUtf8 -Path (Join-Path $out 'verify-python.json') -Text (ConvertTo-Json -InputObject $pythonResult -Depth 8)
$pythonResult.Summary | Format-Table -AutoSize
if ($IncludeWindowsTrustProbe) {
    if ($KnownTlsInspection) {
        Write-Warning 'Windows direct TLS probe skipped: TLS inspection declared; status remains UNKNOWN.'
    } else {
        $windowsResult=Invoke-AuditWindowsTlsSet
        Write-AuditUtf8 -Path (Join-Path $out 'verify-windows-trust.json') -Text (ConvertTo-Json -InputObject $windowsResult -Depth 8)
        $windowsResult.Summary | Format-Table -AutoSize
    }
}
