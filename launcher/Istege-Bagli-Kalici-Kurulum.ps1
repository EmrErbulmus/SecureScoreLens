# =====================================================================
#  ISTEGE BAGLI - Bu dosyayi calistirmak ZORUNDA DEGILSINIZ.
#
#  BASLAT.cmd zaten kurulum olmadan calisir. Bu betik yalnizca
#  "Invoke-SecureScoreLens" komutunu her PowerShell penceresinde
#  kullanilabilir yapmak isteyenler icindir.
#
#  Yonetici yetkisi gerektirmez; yalnizca kendi kullanici profilinize
#  kopyalar.
# =====================================================================

[CmdletBinding()]
param(
    # Kurulumu geri alir (kopyalanan klasoru siler)
    [switch] $Kaldir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }

$source = Join-Path $here 'Modul'
$moduleName = 'SecureScoreLens'

# Kullanicinin modul klasorunu PSModulePath'ten oku.
# Dikkat: Belgeler klasoru OneDrive'a yonlendirilmis olabilecegi icin
# yolu elle kurmuyoruz, PowerShell'in kendi listesinden aliyoruz.
$userRoot = $env:PSModulePath -split ';' |
    Where-Object { $_ -and $_.StartsWith($env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase) } |
    Select-Object -First 1

if (-not $userRoot) {
    $userRoot = Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules'
}

$target = Join-Path $userRoot $moduleName

if ($Kaldir) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
        Write-Host "Kaldirildi: $target" -ForegroundColor Green
    } else {
        Write-Host "Kurulu degil, yapilacak bir sey yok." -ForegroundColor DarkGray
    }
    return
}

if (-not (Test-Path -LiteralPath $source)) {
    Write-Host "HATA: 'Modul' klasoru bulunamadi. ZIP tam olarak ayiklanmamis olabilir." -ForegroundColor Red
    exit 1
}

if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
New-Item -ItemType Directory -Path $target -Force | Out-Null
Copy-Item -Path (Join-Path $source '*') -Destination $target -Recurse -Force

Get-ChildItem -LiteralPath $target -Recurse -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue

Import-Module (Join-Path $target "$moduleName.psd1") -Force -ErrorAction Stop

Write-Host ''
Write-Host "Kuruldu: $target" -ForegroundColor Green
Write-Host ''
Write-Host 'SIRADAKI ADIM' -ForegroundColor Cyan
Write-Host '  Bu pencerede komut zaten hazir:' -ForegroundColor Gray
Write-Host '    Invoke-SecureScoreLens' -ForegroundColor White
Write-Host ''
Write-Host '  Yeni bir PowerShell penceresi acarsaniz da dogrudan calisir.' -ForegroundColor Gray
Write-Host '  Kaldirmak icin bu betigi -Kaldir ile calistirin.' -ForegroundColor DarkGray
Write-Host ''
