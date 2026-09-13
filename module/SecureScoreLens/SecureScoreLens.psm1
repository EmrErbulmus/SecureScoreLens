#Requires -Version 5.1
<#
    SecureScoreLens - Microsoft 365 Secure Score degerlendirme modulu.

    Kullanim:
        Install-Module SecureScoreLens -Scope CurrentUser   # bir kez
        Invoke-SecureScoreLens                                    # her degerlendirme

    Kimlik dogrulama her calistirmada tarayicida yeniden istenir; hicbir kimlik
    bilgisi diske yazilmaz. Tum Graph izinleri salt-okunurdur.
#>

$script:AssetRoot = Join-Path $PSScriptRoot 'assets'

function ConvertTo-IsoDates {
    param($Node)
    if ($null -eq $Node) { return $null }
    if ($Node -is [datetime])       { return $Node.ToString('o') }
    if ($Node -is [datetimeoffset]) { return $Node.ToString('o') }
    if ($Node -is [string])         { return $Node }
    if ($Node -is [System.Collections.IDictionary]) {
        $copy = @{}
        foreach ($key in @($Node.Keys)) { $copy[$key] = ConvertTo-IsoDates $Node[$key] }
        return $copy
    }
    if ($Node -is [System.Collections.IEnumerable]) {
        $list = @()
        foreach ($item in $Node) { $list += ,(ConvertTo-IsoDates $item) }
        return $list
    }
    if ($Node -is [psobject] -and $Node.PSObject.Properties.Count) {
        $copy = @{}
        foreach ($prop in $Node.PSObject.Properties) {
            $copy[$prop.Name] = ConvertTo-IsoDates $prop.Value
        }
        return $copy
    }
    return $Node
}

# --------------------------------------------------------------------------- #
# Browser sign-in with Microsoft's own consent screen
#
# The authorisation-code + PKCE flow is driven directly so that "prompt=consent"
# can be passed. That parameter forces Microsoft to display its own
# "Permissions requested ... Accept / Cancel" page on EVERY run, listing each
# scope the assessment asks for. A public client is used, so no secret exists
# anywhere, and the token is kept in a variable for the lifetime of this process
# only - nothing is written to disk.
# --------------------------------------------------------------------------- #
$GraphPowerShellClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'   # Microsoft Graph PowerShell (public client)

function New-CodeVerifier {
    $bytes = New-Object byte[] 64
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ([Convert]::ToBase64String($bytes) -replace '\+','-' -replace '/','_' -replace '=','')
}

function Get-CodeChallenge {
    param([string] $Verifier)
    $sha   = [Security.Cryptography.SHA256]::Create()
    $hash  = $sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Verifier))
    return ([Convert]::ToBase64String($hash) -replace '\+','-' -replace '/','_' -replace '=','')
}

function Invoke-ConsentSignIn {
    <#
        Opens the Microsoft consent page, waits for the redirect on a loopback
        port and exchanges the authorisation code for an access token.
        Returns a hashtable with AccessToken / Account / TenantId / Scopes.
    #>
    param(
        [Parameter(Mandatory)][string[]] $Scopes,
        [string] $Tenant = 'organizations',
        [int]    $TimeoutSeconds = 300
    )

    $verifier  = New-CodeVerifier
    $challenge = Get-CodeChallenge -Verifier $verifier
    $state     = [guid]::NewGuid().ToString('N')

    # Loopback listener on a free port - no URL ACL or admin rights needed
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $redirect = "http://localhost:$port/"

    # Fully qualify each scope; bare names are ambiguous at the /authorize endpoint
    $full = $Scopes | ForEach-Object {
        if ($_ -match '^https?://') { $_ } else { "https://graph.microsoft.com/$_" }
    }
    $scopeText = ($full -join ' ') + ' offline_access openid profile'
    $query = @(
        "client_id=$GraphPowerShellClientId"
        'response_type=code'
        "redirect_uri=$([Uri]::EscapeDataString($redirect))"
        "scope=$([Uri]::EscapeDataString($scopeText))"
        "code_challenge=$challenge"
        'code_challenge_method=S256'
        "state=$state"
        'prompt=consent'          # <- always show the Permissions requested page
    ) -join '&'
    $authUrl = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize?$query"

    Write-Host '    Tarayicida Microsoft izin ekrani aciliyor...' -ForegroundColor Gray
    Write-Host '    Listelenen yetkileri inceleyip "Accept" ile onaylayin.' -ForegroundColor Gray

    # Prefer a dedicated app-mode window with a throwaway profile: we own that
    # window, so it can be closed automatically once consent is given, and the
    # profile is deleted afterwards so no session is cached anywhere.
    $browser     = Get-ChromiumPath
    $browserProc = $null
    $tempProfile = $null
    if ($browser) {
        $tempProfile = Join-Path $env:TEMP ('ss-auth-' + [guid]::NewGuid().ToString('N'))

        # Pre-seed the throwaway profile so the browser skips its entire
        # first-run experience: no welcome tab, no sync promo, no sign-in
        # prompt, no default-browser question. Only the consent page appears.
        try {
            New-Item -ItemType Directory -Path (Join-Path $tempProfile 'Default') -Force | Out-Null
            # Presence of this marker tells Chromium the first run already happened
            Set-Content -Path (Join-Path $tempProfile 'First Run') -Value '' -NoNewline -Encoding ASCII

            $prefs = @{
                browser = @{ has_seen_welcome_page = $true; check_default_browser = $false
                             show_home_button      = $false }
                profile = @{ exit_type = 'Normal'; exited_cleanly = $true
                             password_manager_enabled = $false }
                sync    = @{ suppress_start = $true }
                signin  = @{ allowed = $false; allowed_on_next_startup = $false }
                session = @{ restore_on_startup = 5 }
                first_run_tabs = @()
            } | ConvertTo-Json -Depth 6 -Compress
            [IO.File]::WriteAllText((Join-Path $tempProfile 'Default\Preferences'), $prefs,
                                    (New-Object Text.UTF8Encoding($false)))

            $localState = @{
                browser = @{ first_run_finished = $true; enabled_labs_experiments = @() }
                edge    = @{ services = @{ sign_in_status = 0 } }
                profile = @{ info_cache = @{} }
            } | ConvertTo-Json -Depth 6 -Compress
            [IO.File]::WriteAllText((Join-Path $tempProfile 'Local State'), $localState,
                                    (New-Object Text.UTF8Encoding($false)))
        } catch { }

        $browserArgs = @(
            "--user-data-dir=$tempProfile"
            '--no-first-run'
            '--no-default-browser-check'
            '--disable-sync'
            '--disable-signin-promo'
            '--disable-background-networking'
            '--disable-component-update'
            '--disable-default-apps'
            '--disable-client-side-phishing-detection'
            '--no-service-autorun'
            '--noerrdialogs'
            '--no-pings'
            '--disable-features=EdgeFirstRunExperience,msEdgeWelcome,msImplicitSignin,ImplicitSignIn,EdgeSyncPromo,Translate,PrivacySandboxSettings4'
            '--window-size=520,720'
            "--app=$authUrl"
        )
        try {
            $browserProc = Start-Process -FilePath $browser -ArgumentList $browserArgs -PassThru
        } catch {
            $browserProc = $null
            $tempProfile = $null
        }
    }
    if (-not $browserProc) {
        # No Chromium browser available - fall back to the default browser.
        Start-Process $authUrl | Out-Null
    }

    try {
        $accept = $listener.AcceptTcpClientAsync()
        if (-not $accept.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
            throw "Onay icin beklenen sure doldu ($TimeoutSeconds sn)."
        }
        $client = $accept.Result
        $stream = $client.GetStream()

        $buffer = New-Object byte[] 8192
        $read   = $stream.Read($buffer, 0, $buffer.Length)
        $request = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        $requestLine = ($request -split "`r?`n")[0]          # GET /?code=...&state=... HTTP/1.1
        $rawQuery = ''
        if ($requestLine -match '^GET\s+([^\s]+)') { $rawQuery = $matches[1] }

        # Ignore anything that is not the callback we are waiting for, so a stray
        # local request cannot consume the single accepted connection.
        $isCallback = $rawQuery -match '^/(\?|$)'

        $params = @{}
        if ($isCallback -and $rawQuery -match '\?(.*)$') {
            foreach ($pair in ($matches[1] -split '&')) {
                $kv = $pair -split '=', 2
                if ($kv.Count -eq 2) { $params[$kv[0]] = [Uri]::UnescapeDataString($kv[1].Replace('+',' ')) }
            }
        }

        $ok = $params.ContainsKey('code')

        # On success the tab closes itself and the operator is back in PowerShell
        # with no extra click. Browsers refuse window.close() on tabs they did not
        # open via script, so a single quiet line is left behind in that case.
        # A cancelled or failed consent still shows a visible explanation.
        if ($ok) {
            # Nothing to show: the window we opened is closed programmatically
            # below. The fallback path (default browser) gets a page that tries
            # to close itself and otherwise leaves one quiet line.
            if ($browserProc) {
                # Plain white page with no title text - it is on screen for a
                # fraction of a second before the window is closed below.
                $body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title> </title>' +
                        '<style>html,body{background:#fff;margin:0}</style></head><body></body></html>'
            }
            else {
                $body = @"
<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Onaylandi</title>
<style>body{font:13px Calibri,"Segoe UI",sans-serif;color:#98A2B3;background:#fff;
margin:0;display:flex;align-items:center;justify-content:center;height:100vh}</style>
<script>
(function(){
  try { window.open('', '_self'); window.close(); } catch (e) {}
  setTimeout(function(){
    try { window.close(); } catch (e) {}
    var m = document.getElementById('m'); if (m) { m.style.display = 'block'; }
  }, 250);
})();
</script></head>
<body><div id="m" style="display:none">Onaylandi &mdash; bu sekmeyi kapatabilirsiniz.</div></body></html>
"@
            }
        }
        else {
            # Never reflect the raw query string back into the page. Anything that
            # reaches this listener is untrusted - the redirect is not guaranteed to
            # be the browser's - so map the OAuth error code to a fixed message and
            # fall back to a generic one. Nothing attacker-supplied is rendered.
            $code = if ($params.ContainsKey('error')) { "$($params['error'])".ToLowerInvariant() } else { '' }
            $why = switch -Exact ($code) {
                'access_denied'          { 'Yetki onayi verilmedi.' }
                'consent_required'       { 'Yonetici onayi gerekiyor.' }
                'interaction_required'   { 'Ek etkilesim gerekiyor.' }
                'login_required'         { 'Oturum acilmasi gerekiyor.' }
                'invalid_request'        { 'Istek gecersiz.' }
                'unauthorized_client'    { 'Uygulama bu tenant icin yetkili degil.' }
                'server_error'           { 'Microsoft tarafinda gecici bir hata olustu.' }
                'temporarily_unavailable'{ 'Servis gecici olarak kullanilamiyor.' }
                default                  { 'Yetki onayi tamamlanmadi.' }
            }
            $body = @"
<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8"><title>Islem iptal edildi</title>
<style>body{font:15px/1.6 Calibri,"Segoe UI",sans-serif;background:#F5F7FA;margin:0;
display:flex;align-items:center;justify-content:center;height:100vh}
.c{background:#fff;border:1px solid #EAECF0;border-radius:12px;padding:36px 44px;
text-align:center;box-shadow:0 1px 3px rgba(16,24,40,.08);max-width:460px}
h1{color:#B42318;font-size:20px;margin:0 0 10px}p{color:#475467;margin:0;font-size:14px}
</style></head><body><div class="c"><h1>Islem iptal edildi</h1>
<p>$why</p><p style="margin-top:10px">PowerShell penceresine donebilirsiniz.</p></div></body></html>
"@
        }

        $bytes = [Text.Encoding]::UTF8.GetBytes($body)
        $head  = "HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
        $headBytes = [Text.Encoding]::ASCII.GetBytes($head)
        $stream.Write($headBytes, 0, $headBytes.Length)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()
        $client.Close()

        # Close the app-mode window we opened, so no page is left on screen.
        if ($browserProc) {
            Start-Sleep -Milliseconds 150          # let the HTTP response drain
            Close-BrowserProcess -Process $browserProc
        }

        if ($params.ContainsKey('error')) {
            $desc = if ($params.ContainsKey('error_description')) { $params['error_description'] } else { '' }
            throw "Yetki onayi verilmedi: $($params['error']). $desc"
        }
        if (-not $ok) { throw 'Yetki onayi alinamadi (kod donmedi).' }
        if ($params['state'] -ne $state) { throw 'Guvenlik dogrulamasi basarisiz (state uyusmuyor).' }

        $tokenBody = @{
            client_id     = $GraphPowerShellClientId
            grant_type    = 'authorization_code'
            code          = $params['code']
            redirect_uri  = $redirect
            code_verifier = $verifier
            scope         = $scopeText
        }
        $token = Invoke-RestMethod -Method Post -ContentType 'application/x-www-form-urlencoded' `
                    -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Body $tokenBody

        # Read account + tenant from the id_token / access_token payload (no extra call)
        $account = ''; $tid = ''
        try {
            $part = ($token.access_token -split '\.')[1].Replace('-','+').Replace('_','/')
            switch ($part.Length % 4) { 2 { $part += '==' } 3 { $part += '=' } }
            $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($part)) | ConvertFrom-Json
            $account = $claims.upn; if (-not $account) { $account = $claims.preferred_username }
            $tid = $claims.tid
        } catch { }

        return @{
            AccessToken = $token.access_token
            Account     = $account
            TenantId    = $tid
            Scopes      = @(($token.scope -split ' ') | Where-Object { $_ })
        }
    }
    finally {
        $listener.Stop()
        if ($browserProc) { Close-BrowserProcess -Process $browserProc }
        if ($tempProfile -and (Test-Path $tempProfile)) {
            # The browser releases the profile a moment after exiting
            foreach ($try in 1..5) {
                Start-Sleep -Milliseconds 300
                try { Remove-Item $tempProfile -Recurse -Force -EA Stop; break } catch { }
            }
        }
    }
}

function Get-ChromiumPath {
    # A Chromium browser can be opened in app mode with its own profile, which
    # gives us a window we own and can therefore close again afterwards.
    $candidates = @(
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    return $null
}

function Close-BrowserProcess {
    <#
        Close the consent window we opened, quietly.

        Order matters: killing the renderer children first makes Chromium think
        it crashed and it paints a "This page is having a problem"
        (RESULT_CODE_KILLED) screen for a moment. So ask the window to close
        normally first, and if it will not, terminate the top-level process -
        which takes the window with it - before sweeping any leftovers.

        Only ever called with a process this module started itself.
    #>
    param([System.Diagnostics.Process] $Process)
    if (-not $Process) { return }

    $pidToClose = $Process.Id

    # 1. Graceful close - no crash screen, no orphaned renderers
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) { [void]$Process.CloseMainWindow() }
    } catch { }

    # 2. Give it a moment to shut down on its own
    for ($i = 0; $i -lt 12; $i++) {
        Start-Sleep -Milliseconds 100
        try {
            $Process.Refresh()
            if ($Process.HasExited) { break }
        } catch { break }
    }

    # 3. Still up? Terminate the top-level process; the window disappears at once
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            Stop-Process -Id $pidToClose -Force -ErrorAction SilentlyContinue
        }
    } catch { }

    # 4. Sweep any helper processes left behind
    try {
        Start-Sleep -Milliseconds 150
        $kids = Get-CimInstance Win32_Process -Filter "ParentProcessId=$pidToClose" `
                    -ErrorAction SilentlyContinue
        foreach ($k in $kids) {
            Stop-Process -Id ([int]$k.ProcessId) -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

function Set-ConsoleForeground {
    # After the browser step, pull this console back in front so the operator
    # does not have to alt-tab. Purely cosmetic - never allowed to fail the run.
    try {
        if (-not ('Native.WinFg' -as [type])) {
            Add-Type -Namespace Native -Name WinFg -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@ -ErrorAction SilentlyContinue
        }
        $h = (Get-Process -Id $PID).MainWindowHandle
        if ($h -ne [IntPtr]::Zero) {
            [Native.WinFg]::ShowWindow($h, 9)   | Out-Null   # SW_RESTORE
            [Native.WinFg]::SetForegroundWindow($h) | Out-Null
        }
    } catch { }
}

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string] $Uri, [Parameter(Mandatory)][string] $Token)
    if ($Uri -notmatch '^https?://') { $Uri = 'https://graph.microsoft.com' + $Uri }
    return Invoke-RestMethod -Method GET -Uri $Uri -Headers @{
        Authorization     = "Bearer $Token"
        'Accept-Language' = 'tr-TR,tr;q=0.9,en;q=0.8'
    }
}

function Get-Val {
    param($Object, [string] $Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Resolve-PythonPath {
    # Returns the path to a usable Python 3.8+ interpreter, or $null.
    foreach ($c in @('python', 'python3', 'py')) {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $v = & $cmd.Source --version 2>&1
            if ("$v" -match '(\d+)\.(\d+)') {
                if ([int]$Matches[1] -ge 3 -and [int]$Matches[2] -ge 8) { return $cmd.Source }
            }
        } catch { }
    }
    return $null
}

function Show-Banner {
    <#
        Start-up banner. Drawn with plain ASCII on purpose: Windows PowerShell 5.1
        consoles frequently run a code page that mangles box-drawing characters,
        and a broken banner is a bad first impression for a security tool.
    #>
    $art = @(
        '  ______     ______  ',
        ' |  ____|   |  ____| ',
        ' | |__      | |__    ',
        ' |  __|     |  __|   ',
        ' | |____ _  | |____ _',
        ' |______(_) |______(_)'
    )
    Write-Host ''
    foreach ($line in $art) { Write-Host $line -ForegroundColor Cyan }
    Write-Host ''
    Write-Host '  Microsoft 365 Secure Score Degerlendirmesi' -ForegroundColor White
    Write-Host '  Salt-okunur guvenlik durusu analizi' -ForegroundColor DarkGray
    Write-Host ('  ' + ('-' * 44)) -ForegroundColor DarkGray
}

function Write-Step { param($m) Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "    OK  $m" -ForegroundColor Green }
function Write-Warn2{ param($m) Write-Host "    !   $m" -ForegroundColor Yellow }

# --------------------------------------------------------------------------- #
# Remove anything credential-shaped that may be lying around
# --------------------------------------------------------------------------- #
function Clear-AuthArtifacts {
    param([switch] $IncludeConfig)

    # Microsoft Graph PowerShell / MSAL token caches
    $cachePaths = @(
        "$env:USERPROFILE\.graph",
        "$env:LOCALAPPDATA\.IdentityService\msal.cache",
        "$env:LOCALAPPDATA\.IdentityService\msal.cache.bin"
    )
    foreach ($p in $cachePaths) {
        if (Test-Path $p) {
            try { Remove-Item $p -Recurse -Force -ErrorAction Stop; Write-Ok "Token onbellegi temizlendi: $p" }
            catch { Write-Warn2 "Temizlenemedi (kullanimda olabilir): $p" }
        }
    }

    if ($IncludeConfig) {
        # Both names are cleaned: installations made before the project was
        # renamed may still have left a folder under the old one.
        $cfgDir = Join-Path $env:LOCALAPPDATA 'SecureScoreLens'
        $legacyDir = Join-Path $env:LOCALAPPDATA 'SecureScoreAssessment'
        foreach ($d in @($cfgDir, $legacyDir)) {
            if (Test-Path $d) {
                try { Remove-Item $d -Recurse -Force -ErrorAction Stop
                      Write-Ok "Kayitli yapilandirma silindi: $d" }
                catch { Write-Warn2 "Yapilandirma silinemedi: $d" }
            }
        }
    }
}

function Clear-SecureScoreCredential {
    <#
    .SYNOPSIS
        Eski surumlerden kalan sifreli yapilandirmayi ve token onbelleklerini siler.
    .EXAMPLE
        Clear-SecureScoreCredential
    #>
    [CmdletBinding()]
    param()
    Write-Step 'Kayitli kimlik bilgileri ve token onbellekleri siliniyor'
    Clear-AuthArtifacts -IncludeConfig
    Write-Host "`nTemizlik tamamlandi." -ForegroundColor Green
}


function Invoke-SecureScoreLens {
    <#
    .SYNOPSIS
        Microsoft 365 tenant'i icin salt-okunur Secure Score degerlendirmesi calistirir.

    .DESCRIPTION
        Tarayicida Microsoft'un izin ekranini acar, onay alindiktan sonra Secure Score
        puanini ve tum iyilestirme islemlerini okur, Turkce bir HTML rapor uretir.
        Tenant uzerinde hicbir degisiklik yapilmaz. Kimlik bilgisi saklanmaz.

    .PARAMETER Logo
        Rapor basligina gomulecek logo dosyasi (png/jpg/gif/svg/webp, en fazla 2 MB).

    .PARAMETER BrandColor
        Kurumsal vurgu rengi (#RRGGBB). Risk renk paletini etkilemez.

    .PARAMETER Provider
        Degerlendirmeyi hazirlayan hizmet saglayici adi. Baslik ve alt bilgide gosterilir.

    .PARAMETER Customer
        Raporda gosterilecek musteri adi. Belirtilmezse tenant'in kurum adi kullanilir.

    .PARAMETER Path
        Rapor klasoru. Varsayilan: .\SecureScoreReport

    .PARAMETER TenantId
        Hedef tenant. Belirtilmezse oturum acilan tenant kullanilir.

    .PARAMETER HistoryDays
        Trend icin cekilecek olcum sayisi (varsayilan 30).

    .PARAMETER Demo
        Sentetik ornek veriyle calistir (tenant'a baglanmaz).

    .PARAMETER SelfTest
        Analiz motorunun dogrulama testlerini calistir.

    .EXAMPLE
        Invoke-SecureScoreLens

    .EXAMPLE
        Invoke-SecureScoreLens -Customer "KocSistem" -Path C:\Raporlar
    #>
    [CmdletBinding()]
    param(
        [string] $Customer,
        [string] $Logo,
        [string] $BrandColor,
        [string] $Provider,
        [Alias('OutputFolder')]
        [string] $Path,
        [string] $TenantId,
        [int]    $HistoryDays = 30,
        [switch] $AppOnly,
        [string] $ClientId,
        [switch] $Demo,
        [switch] $SelfTest,
        [switch] $SkipPythonInstall
    )

    $AssetRoot  = $script:AssetRoot
    $enginePath = Join-Path $AssetRoot 'secure_score_assessment.py'
    $exitCode   = 1

    # Reports land in the caller's current folder unless -Path was supplied.
    # Resolve to a full path so the report location is never ambiguous.
    $OutputFolder = $Path
    if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
        $OutputFolder = Join-Path (Get-Location).ProviderPath 'SecureScoreReport'
    }
    elseif (-not [IO.Path]::IsPathRooted($OutputFolder)) {
        $OutputFolder = Join-Path (Get-Location).ProviderPath $OutputFolder
    }

    Show-Banner
    Write-Host "  Kimlik dogrulama her calistirmada yeniden istenir; hicbir bilgi saklanmaz." -ForegroundColor DarkGray
    Write-Host "  Rapor klasoru: $OutputFolder" -ForegroundColor DarkGray

    # --------------------------------------------------------------------------- #
    # Python
    # --------------------------------------------------------------------------- #
    $python = Resolve-PythonPath
    if (-not $python -and -not $SkipPythonInstall) {
        # Install the runtime on the user's behalf rather than making them do it,
        # so the module behaves like any other self-contained PowerShell tool.
        Write-Warn2 'Python 3 bulunamadi, winget ile kuruluyor (tek seferlik)...'
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            try {
                winget install -e --id Python.Python.3.12 --scope user `
                    --accept-source-agreements --accept-package-agreements | Out-Null
            } catch { }
            $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                        [Environment]::GetEnvironmentVariable('Path', 'User')
            $python = Resolve-PythonPath
        }
    }
    if (-not $python) {
        throw ("Python 3.8+ bulunamadi. Kurmak icin: winget install -e --id Python.Python.3.12 " +
               "(kurulumdan sonra PowerShell'i yeniden acin).")
    }
    if (-not (Test-Path $enginePath)) {
        throw "Assessment motoru bulunamadi: $enginePath"
    }

    $common = @()
    if ($Customer)     { $common += @('--customer', $Customer) }
    if ($Logo) {
        # Resolve before handing it over: a relative path would otherwise be
        # read against the engine's working directory, not the caller's.
        $logoFull = (Resolve-Path -LiteralPath $Logo -ErrorAction SilentlyContinue)
        if ($logoFull) { $common += @('--logo', $logoFull.Path) }
        else { Write-Warn2 "Logo dosyasi bulunamadi, atlandi: $Logo" }
    }
    if ($BrandColor)   { $common += @('--brand-color', $BrandColor) }
    if ($Provider)     { $common += @('--provider', $Provider) }

    if ($SelfTest) { & $python $enginePath --self-test; return }
    if ($Demo)     {
        & $python $enginePath --demo --out $OutputFolder @common
        $r = Get-ChildItem $OutputFolder -Filter '*.html' -EA SilentlyContinue |
             Sort-Object LastWriteTime -Desc | Select-Object -First 1
        if ($r) { Start-Process $r.FullName }
        return
    }

    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    $exitCode = 1

    try {
        if ($AppOnly) {
            # ------------------------------------------------------------------- #
            # App-only: secret typed in every run, never written to disk
            # ------------------------------------------------------------------- #
            Write-Step 'Uygulama kimligi ile calistirma (bilgiler her seferinde istenir)'
            if (-not $TenantId) { $TenantId = Read-Host 'Tenant ID veya domain' }
            if (-not $ClientId) { $ClientId = Read-Host 'Uygulama (client) ID' }
            $secure = Read-Host 'Client secret' -AsSecureString
            $plain  = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
            try {
                $env:SECURESCORE_TENANT_ID     = $TenantId
                $env:SECURESCORE_CLIENT_ID     = $ClientId
                $env:SECURESCORE_CLIENT_SECRET = $plain
                Write-Step 'Degerlendirme calisiyor (salt-okunur)'
                & $python $enginePath --history-days $HistoryDays --out $OutputFolder @common
                $exitCode = $LASTEXITCODE
            }
            finally {
                $plain = $null
                Remove-Item Env:SECURESCORE_CLIENT_SECRET -EA SilentlyContinue
                Remove-Item Env:SECURESCORE_TENANT_ID     -EA SilentlyContinue
                Remove-Item Env:SECURESCORE_CLIENT_ID     -EA SilentlyContinue
                [GC]::Collect()
            }
        }
        else {
            # ------------------------------------------------------------------- #
            # Interactive: browser sign-in every run, token kept in-process only
            # ------------------------------------------------------------------- #
            # ------------------------------------------------------------------- #
            # Sign in. Microsoft's own "Permissions requested" page is shown every
            # run (prompt=consent), listing each scope with an Accept / Cancel
            # choice - the consent decision belongs to the tenant admin, in the
            # browser, not to a prompt in this console.
            # ------------------------------------------------------------------- #
            $requested = @(
                [pscustomobject]@{ Izin = 'SecurityEvents.Read.All'; Tur = 'Zorunlu'
                                   Aciklama = 'Secure Score puani ve kontrol maddelerini okur' }
                [pscustomobject]@{ Izin = 'Organization.Read.All';   Tur = 'Opsiyonel'
                                   Aciklama = 'Raporda gosterilecek kurum adini ve alan adini okur' }
            )

            Write-Step 'Yetki onayi tarayicida isteniyor (her calistirmada)'
            foreach ($p in $requested) {
                Write-Host ("    {0,-26} {1,-10} {2}" -f $p.Izin, $p.Tur, $p.Aciklama) -ForegroundColor Gray
            }
            Write-Host '    Tum yetkiler SALT-OKUNURDUR; yazma/degistirme/silme istenmez.' -ForegroundColor Green

            $tenantTarget = if ($TenantId) { $TenantId } else { 'organizations' }
            $auth = Invoke-ConsentSignIn -Scopes @($requested.Izin) -Tenant $tenantTarget
            $token = $auth.AccessToken
            Set-ConsoleForeground

            Write-Ok "Onaylandi ve baglanildi: $($auth.Account)"
            if ($auth.TenantId) { Write-Ok "Tenant  : $($auth.TenantId)" }

            # Verify the consent silently. The full granted-scope list is not printed:
            # the token may carry scopes consented earlier for other purposes, which is
            # noise here. Only a MISSING permission is worth reporting.
            $granted = @($auth.Scopes | ForEach-Object { ($_ -split '/')[-1] })
            foreach ($p in $requested) {
                if ($granted -notcontains $p.Izin) {
                    if ($p.Tur -eq 'Zorunlu') {
                        throw "Zorunlu yetki verilmedi: $($p.Izin). Global Administrator onayi gerekiyor."
                    }
                    Write-Warn2 "Opsiyonel yetki verilmedi: $($p.Izin) - $($p.Aciklama)"
                }
            }

            Write-Step 'Secure Score verileri okunuyor'
            $scores = Get-Val (Invoke-GraphGet -Token $token `
                        -Uri "/v1.0/security/secureScores?`$top=$HistoryDays") 'value'

            $profiles = @()
            $uri = '/v1.0/security/secureScoreControlProfiles'
            while ($uri) {
                $page = Invoke-GraphGet -Token $token -Uri $uri
                $profiles += Get-Val $page 'value'
                $uri = Get-Val $page '@odata.nextLink'
            }

            $org = $null
            try { $org = @(Get-Val (Invoke-GraphGet -Token $token -Uri '/v1.0/organization') 'value')[0] }
            catch { Write-Warn2 'Kurum bilgisi okunamadi (Organization.Read.All izni olmayabilir).' }
            Write-Ok "$(@($scores).Count) olcum, $(@($profiles).Count) kontrol profili alindi"

            $tenantObj = @{}
            if ($org) {
                # Prefer the domain flagged isDefault; fall back to the first
                # verified domain so tenants without that flag still report one.
                $defaultDomain = $null
                $allDomains    = @()
                foreach ($d in @(Get-Val $org 'verifiedDomains')) {
                    $n = Get-Val $d 'name'
                    if ($n) { $allDomains += $n }
                    if ((Get-Val $d 'isDefault') -and -not $defaultDomain) { $defaultDomain = $n }
                }
                if (-not $defaultDomain -and $allDomains.Count -gt 0) {
                    $defaultDomain = $allDomains[0]
                }
                $tenantObj = @{
                    id              = Get-Val $org 'id'
                    displayName     = Get-Val $org 'displayName'
                    domain          = $defaultDomain
                    verifiedDomains = $allDomains
                }
                Write-Ok "Kurum: $($tenantObj.displayName)"
            }

            $raw = Join-Path $OutputFolder ("securescore-raw-{0}.json" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $payload = ConvertTo-IsoDates @{ tenant          = $tenantObj
                                             secureScores    = $scores
                                             controlProfiles = $profiles }
            $json = $payload | ConvertTo-Json -Depth 12 -Compress
            # BOM-less UTF-8: Windows PowerShell's Set-Content -Encoding UTF8 writes a BOM
            [IO.File]::WriteAllText($raw, $json, (New-Object Text.UTF8Encoding($false)))

            Write-Step 'Rapor olusturuluyor'
            & $python $enginePath --offline-input $raw --out $OutputFolder @common
            $exitCode = $LASTEXITCODE
        }

        if ($exitCode -ne 0) {
            Write-Host "`nRapor uretilemedi (cikis kodu $exitCode). Yukaridaki hata mesajina bakin." -ForegroundColor Red
            return
        }
        $report = Get-ChildItem $OutputFolder -Filter '*dashboard*.html' -EA SilentlyContinue |
                  Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) } |
                  Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($report) {
            Write-Host "`nRapor aciliyor: $($report.FullName)" -ForegroundColor Green
            Start-Process $report.FullName
        }
    }
    finally {
        # Drop the token from memory and leave nothing behind on disk
        $token = $null
        $auth  = $null
        if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
            try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        }
        Clear-AuthArtifacts
        [GC]::Collect()
        Write-Host "`nOturum kapatildi, token bellekten silindi." -ForegroundColor Gray
    }

    if ($exitCode -ne 0) {
        Write-Warn2 "Degerlendirme tamamlanamadi (cikis kodu $exitCode)."
    }
}

# Backwards compatibility: the command was called Invoke-SecureScoreAssessment
# before the project was named SecureScoreLens. The alias keeps existing
# scripts, shortcuts and documentation working.
Set-Alias -Name Invoke-SecureScoreAssessment -Value Invoke-SecureScoreLens

Export-ModuleMember -Function Invoke-SecureScoreLens, Clear-SecureScoreCredential `
                    -Alias Invoke-SecureScoreAssessment
