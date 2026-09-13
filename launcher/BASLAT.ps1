# =====================================================================
#  Microsoft 365 Secure Score Degerlendirmesi - Baslatici
#  Surum: 2.1
#
#  KURULUM GEREKTIRMEZ. Bu betik, yaninda duran Modul klasorunu
#  dogrudan yukler ve degerlendirmeyi baslatir. Sisteme hicbir sey
#  kurmaz, PSModulePath'i degistirmez, yonetici yetkisi istemez.
#
#  Calistirmak icin: BASLAT.cmd dosyasina cift tiklayin.
# =====================================================================

[CmdletBinding()]
param(
    # Raporun yazilacagi klasor. Varsayilan: bu klasorun altindaki Raporlar
    [string] $OutputFolder,

    # Gercek tenant'a baglanmadan ornek veriyle rapor uretir
    [switch] $Demo,

    # Analiz motorunun ic dogrulama testlerini calistirir
    [switch] $SelfTest,

    # Raporda gosterilecek musteri/kurum adi
    [string] $Customer,

    # Hedef tenant. Belirtilmezse oturum acilan tenant kullanilir.
    [string] $TenantId
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# --- 1. Bu betigin bulundugu klasoru guvenilir sekilde bul ------------
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $here) {
    Write-Host "HATA: Betigin klasoru belirlenemedi. Lutfen BASLAT.cmd ile calistirin." -ForegroundColor Red
    exit 1
}

$manifest = Join-Path $here 'Modul\SecureScoreLens.psd1'

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host '   Microsoft 365 Secure Score Degerlendirmesi' -ForegroundColor Cyan
Write-Host '  ============================================================' -ForegroundColor DarkCyan
Write-Host ''

# --- 2. Paket butunlugu ----------------------------------------------
if (-not (Test-Path -LiteralPath $manifest)) {
    Write-Host "HATA: Modul dosyalari bulunamadi." -ForegroundColor Red
    Write-Host "  Beklenen konum: $manifest" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host "  En yaygin sebep: ZIP dosyasi tam olarak cikarilmadi." -ForegroundColor Yellow
    Write-Host "  ZIP'e sag tiklayin > 'Tumunu ayikla' deyin ve ayiklanan" -ForegroundColor Yellow
    Write-Host "  klasorun icindeki BASLAT.cmd dosyasini calistirin." -ForegroundColor Yellow
    Write-Host ''
    exit 1
}

# --- 3. PowerShell surumu --------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "HATA: Windows PowerShell 5.1 veya uzeri gerekir." -ForegroundColor Red
    Write-Host "  Bulunan surum: $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
    exit 1
}

# --- 4. Internetten indirilen dosyalarin engelini kaldir --------------
#     Windows, indirilen ZIP'ten cikan her dosyayi "bloke" isaretler;
#     bu isaret modulun yuklenmesini engelleyebilir. Sadece bu paketin
#     kendi dosyalarina dokunuyoruz.
try {
    Get-ChildItem -LiteralPath $here -Recurse -File -ErrorAction SilentlyContinue |
        Unblock-File -ErrorAction SilentlyContinue
} catch {
    # Unblock-File her ortamda bulunmayabilir; kritik degil.
}

# --- 5. Modulu tam yol ile yukle (PSModulePath'e bagimli degil) -------
try {
    Import-Module $manifest -Force -ErrorAction Stop
} catch {
    Write-Host "HATA: Modul yuklenemedi." -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host "  Cozum onerisi: paketi Masaustu gibi kisa bir yola tasiyip" -ForegroundColor Yellow
    Write-Host "  tekrar deneyin (cok uzun dosya yollari sorun cikarabilir)." -ForegroundColor Yellow
    exit 1
}

if (-not (Get-Command Invoke-SecureScoreLens -ErrorAction SilentlyContinue)) {
    Write-Host "HATA: Modul yuklendi ancak komut disa aktarilmadi." -ForegroundColor Red
    Write-Host "  Paket eksik veya bozuk olabilir; yeniden indirin." -ForegroundColor Yellow
    exit 1
}

# --- 6. Rapor klasoru -------------------------------------------------
if (-not $OutputFolder) { $OutputFolder = Join-Path $here 'Raporlar' }
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

# --- 7. Calistir ------------------------------------------------------
$params = @{ Path = $OutputFolder }
if ($Demo)     { $params['Demo']     = $true }
if ($SelfTest) { $params['SelfTest'] = $true }
if ($Customer) { $params['Customer'] = $Customer }
if ($TenantId) { $params['TenantId'] = $TenantId }

try {
    Invoke-SecureScoreLens @params
} catch {
    Write-Host ''
    Write-Host "HATA: Degerlendirme tamamlanamadi." -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  Pencereyi kapatmadan once yukaridaki mesaji not alin.' -ForegroundColor Yellow
    exit 1
}

Write-Host ''
Write-Host "  Raporlar: $OutputFolder" -ForegroundColor Green
Write-Host ''

# Basarili bitis. .cmd sarmalayici bu kodu okuyup pencereyi hemen kapatir.
exit 0
