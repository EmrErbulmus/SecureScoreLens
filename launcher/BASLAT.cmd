@echo off
REM =====================================================================
REM  Microsoft 365 Secure Score Degerlendirmesi
REM  Bu dosyaya CIFT TIKLAYIN. Baska hicbir sey yapmaniza gerek yok.
REM =====================================================================
title Microsoft 365 Secure Score Degerlendirmesi

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0BASLAT.ps1" %*

REM Islem basariyla bittiyse pencere hemen kapanir.
REM Yalnizca hata olustugunda acik kalir ki mesaj okunabilsin.
if errorlevel 1 (
    echo.
    echo Islem hata ile sonlandi. Yukaridaki mesaji not alin.
    echo Pencereyi kapatmak icin bir tusa basin.
    pause >nul
)

exit /b %errorlevel%
