@echo off
echo ============================================================
echo  Luckyware Shield Ultra - Build Script
echo ============================================================

:: Eski build temizle
if exist dist\LuckywareShieldUltra.exe (
    del /f /q dist\LuckywareShieldUltra.exe
    echo [*] Eski EXE silindi.
)

:: Spec dosyasiyla build (UAC admin manifest dahil)
pyinstaller --clean LuckywareShieldUltra.spec

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Build basarili!
    echo [+] EXE: dist\LuckywareShieldUltra.exe
    echo.
    echo [*] EXE uac_admin=True ile derlendi.
    echo [*] Cift tiklandigi zaman otomatik olarak UAC penceresi gorunecek.
) else (
    echo.
    echo [-] Build BASARISIZ. Hata koduna bakin.
)

pause