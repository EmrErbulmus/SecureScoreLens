#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$directory = $null
$probe = $null
$exitCode = 1
$stage = 'Platform'
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw [PlatformNotSupportedException]::new()
    }
    $stage = 'Import'
    $module = Import-Module (Join-Path $PSScriptRoot 'Modul/SecureScoreLens.psd1') -Force -PassThru
    $stage = 'PrepareProbe'
    $candidate = Join-Path $PSScriptRoot ('OutputProbe-' + [Guid]::NewGuid().ToString('N'))
    $created = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop
    $directory = $created.FullName
    $probe = Join-Path $directory 'probe.txt'
    $stage = 'WriteProbe'
    & $module { param($target) Write-PrivateOutputText -Path $target -Text 'SecureScoreLens synthetic output probe' } $probe
    $stage = 'VerifyContent'
    if ([IO.File]::ReadAllText($probe) -cne 'SecureScoreLens synthetic output probe') {
        throw [InvalidOperationException]::new()
    }
    $stage = 'VerifyAcl'
    $acl = Get-Acl -LiteralPath $probe
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowedSids = @($userSid, 'S-1-5-18') | Select-Object -Unique
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne $allowedSids.Count) {
        throw [InvalidOperationException]::new()
    }
    foreach ($sid in $allowedSids) {
        $matching = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
        if ($matching.Count -ne 1 -or $matching[0].IsInherited -or
            $matching[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $matching[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
            throw [InvalidOperationException]::new()
        }
    }
    $stage = 'VerifyCreateNew'
    $overwriteBlocked = $false
    try {
        & $module { param($target) Write-PrivateOutputText -Path $target -Text 'must not overwrite' } $probe
    } catch {
        $overwriteBlocked = $true
    }
    if (-not $overwriteBlocked -or [IO.File]::ReadAllText($probe) -cne 'SecureScoreLens synthetic output probe') {
        throw [InvalidOperationException]::new()
    }
    Write-Output 'OutputProbe=PASS; Content=PASS; ProtectedAcl=PASS; UserAndSystemOnly=PASS; CreateNew=PASS; Authentication=NOT_RUN'
    $exitCode = 0
} catch {
    $failure = $_.Exception
    while ($null -ne $failure.InnerException) { $failure = $failure.InnerException }
    $safePattern = '^Ozel cikti dosyasi yazilamadi\. Asama=(Encode|BuildAcl|PreparePrivate|CreatePrivateFramework|LoadPrivateApi|CreatePrivateModern|Create|SetMode|Write|Flush|Close); Tur=[A-Za-z0-9_]+; HResult=0x[0-9A-F]{8}; Parametre=(None|Other|path|mode|rights|share|bufferSize|options|fileSecurity|fileInfo)\.$'
    if ($failure.Message -cmatch $safePattern) {
        Write-Output $failure.Message
    } else {
        Write-Output ('OutputProbe=FAIL; Asama={0}; Tur={1}; HResult=0x{2:X8}; Authentication=NOT_RUN' -f $stage, $failure.GetType().Name, $failure.HResult)
    }
} finally {
    try {
        if ($null -ne $probe -and [IO.File]::Exists($probe)) { [IO.File]::Delete($probe) }
        if ($null -ne $directory) { [IO.Directory]::Delete($directory, $false) }
        Write-Output 'OutputProbeCleanup=PASS'
    } catch {
        Write-Output 'OutputProbeCleanup=FAIL'
        $exitCode = 1
    }
}
exit $exitCode
