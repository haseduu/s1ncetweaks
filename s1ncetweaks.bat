@echo off
color 0A
chcp 65001 >nul

::Title and Version
title s1nce Tweaks
set Version=1.1

::Enable Delayed Expansion
SetLocal EnableDelayedExpansion

::Set Logfile with timestamp
echo s1nce Tweaks v1.1 Log > s1ncetweaks.log
echo Started: %date% %time% >> s1ncetweaks.log
echo. >> s1ncetweaks.log

::Check For Admin Rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script requires administrator privileges.
    echo Please right-click the script and select "Run as administrator".
    echo Press any key to exit...
    pause >nul
    exit /b
)

::Check For Curl
where curl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] curl is not installed. Please install curl and try again.
    echo This script requires curl to download necessary tools.
    pause
    exit /b
)

::Make Directory In Temp
mkdir "%temp%\s1nceTweaks" 2>nul
set "s1nce=%temp%\s1nceTweaks"



:MainMenu
cls
echo ╔════════════════════════════════════════════════╗
echo ║              S1NCE TWEAKS v%Version%                 ║
echo ╠════════════════════════════════════════════════╣
echo ║                                                ║
echo ║  [1] Download Required Tools                   ║
echo ║  [2] Create System Restore Point               ║
echo ║  [3] Performance Tweaks                        ║
echo ║  [4] Privacy Tweaks                            ║
echo ║  [5] Visual Settings                           ║
echo ║  [6] Network Optimization                      ║
echo ║  [0] Exit                                      ║
echo ║                                                ║
echo ╚════════════════════════════════════════════════╝
echo.
set /p choice=Enter your choice (0-6): 
if "%choice%"=="1" goto DownloadTools
if "%choice%"=="2" goto CreateRestorePoint
if "%choice%"=="3" goto PerformanceTweaks
if "%choice%"=="4" goto PrivacyTweaks
if "%choice%"=="5" goto VisualSettings
if "%choice%"=="6" goto NetworkOptimization
if "%choice%"=="0" goto Exit

echo Invalid option. Please try again.
timeout /t 2 /nobreak >nul
goto MainMenu

:DownloadTools
cls
echo ╔════════════════════════════════════════════════╗
echo ║          DOWNLOADING REQUIRED TOOLS            ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [INFO] This will download tools from trusted sources.
echo [INFO] Files will be saved to: %s1nce%
echo.
echo Downloading required files...
echo.

echo [1/4] DevManView.exe (for device management)
curl -L --silent -o "%s1nce%\DevManView.exe" "https://github.com/haseduu/s1ncetweaks/blob/main/resources/DevManView.exe"
echo [2/4] OOSU10.exe (for privacy settings)
curl -L --silent -o "%s1nce%\OOSU10.exe" "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
echo [3/4] ooshutup10.cfg (configuration file)
curl -L --silent -o "%s1nce%\ooshutup10.cfg" "https://github.com/haseduu/s1ncetweaks/blob/main/resources/ooshutup10.cfg"
echo [4/4] Khorvie.pow (powerplan for max performance)
curl -L --silent -o "C:\Khorvie.pow" "https://github.com/haseduu/s1ncetweaks/blob/main/resources/Khorvie.pow"
echo.
echo Download completed successfully!
echo.
echo Press any key to return to main menu...
pause >nul
goto MainMenu

:CreateRestorePoint
cls
echo ╔════════════════════════════════════════════════╗
echo ║         CREATING SYSTEM RESTORE POINT          ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [INFO] Creating a restore point is HIGHLY RECOMMENDED
echo       before making system changes.
echo.
echo Creating system restore point...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 's1nce Tweaks' -RestorePointType 'MODIFY_SETTINGS'"

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] System restore point created successfully!
) else (
    echo.
    echo [WARNING] Failed to create restore point. System Protection may be disabled.
    echo [INFO] Attempting to enable System Protection...
    powershell -ExecutionPolicy Bypass -Command "Enable-ComputerRestore -Drive 'C:\'"
    echo [INFO] Trying to create restore point again...
    powershell -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 's1nce Tweaks' -RestorePointType 'MODIFY_SETTINGS'"
    
    if %errorlevel% equ 0 (
        echo [SUCCESS] System restore point created successfully!
    ) else (
        echo [ERROR] Failed to create restore point after enabling System Protection.
    )
)
echo.
echo Press any key to return to main menu...
pause >nul
goto MainMenu

:PerformanceTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║             PERFORMANCE TWEAKS                 ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [1] Memory Management Optimization
echo [2] Service Host Optimization
echo [3] Process Mitigations (Performance Boost)
echo [4] Power Tweaks
echo [5] Disable Unnecessary Services
echo [6] Boot Configuration
echo [7] GPU Optimization
echo [8] All Performance Tweaks (Recommended)
echo [9] Back to Main Menu
echo.
set /p perfchoice=Enter your choice (1-9): 
if "%perfchoice%"=="1" goto MemoryTweaks
if "%perfchoice%"=="2" goto ServiceHostTweaks
if "%perfchoice%"=="3" goto MitigationTweaks
if "%perfchoice%"=="4" goto PowerTweaks
if "%perfchoice%"=="5" goto ServiceTweaks
if "%perfchoice%"=="6" goto BootTweaks
if "%perfchoice%"=="7" goto GPUOptimization
if "%perfchoice%"=="8" goto AllPerformanceTweaks
if "%perfchoice%"=="9" goto MainMenu

echo Invalid option. Please try again.
timeout /t 2 /nobreak >nul
goto PerformanceTweaks

:MemoryTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║          MEMORY MANAGEMENT TWEAKS              ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Applying Memory Management Tweaks...
echo [Memory Management] >> s1ncetweaks.log

:: Memory Management Tweaks
echo Setting Control Flow Guard to improve performance...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
echo Setting Exploit Protection settings...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >> s1ncetweaks.log

:: Prefetch and Superfetch settings
echo Optimizing Prefetch and Superfetch...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Process Working Set
echo Optimizing Process Working Set...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

echo.
echo Memory Management optimizations applied successfully.
echo.
echo Press any key to return to Performance Tweaks menu...
pause >nul
goto PerformanceTweaks

:ServiceHostTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║         SERVICE HOST OPTIMIZATION              ║
echo ╚════════════════════════════════════════════════╝
echo.
echo This tweak reduces the number of svchost.exe processes
echo running on your system by setting a higher memory threshold.
echo.
echo Please select your system RAM amount:
echo.
echo [1] 4 GB RAM
echo [2] 8 GB RAM
echo [3] 16 GB RAM
echo [4] 32 GB RAM
echo [5] 64 GB RAM
echo [6] Back to Performance Menu
echo.
set /p ram=Enter your choice (1-7): 

if "%ram%"=="1" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4194304" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 4 GB RAM.
)
if "%ram%"=="2" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "8388608" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 8 GB RAM.
)
if "%ram%"=="3" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "16777216" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 16 GB RAM.
)
if "%ram%"=="4" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "33554432" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 32 GB RAM.
)
if "%ram%"=="5" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "67108864" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 64 GB RAM.
)

if "%ram%"=="6" goto PerformanceTweaks

if "%ram%" NEQ "7" (
    echo.
    echo Service Host optimizations applied successfully.
    echo.
    echo Press any key to return to Performance Tweaks menu...
    pause >nul
)
goto PerformanceTweaks

:MitigationTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║          PROCESS MITIGATION TWEAKS             ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [WARNING] These tweaks disable certain security features to improve
echo          performance. This may reduce protection against some exploits.
echo.
echo [1] Apply Standard Mitigations (Recommended)
echo [2] Apply Aggressive Mitigations (Performance Focus)
echo [3] Back to Performance Menu
echo.
set /p mitigation=Enter your choice (1-3): 

if "%mitigation%"=="1" (
    echo Applying Standard Process Mitigation Tweaks...
    echo [Process Mitigations - Standard] >> s1ncetweaks.log

    :: Disable some mitigations but keep essential security
    powershell -Command "Set-ProcessMitigation -System -Disable CFG, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy" >> s1ncetweaks.log
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222222222222222222" /f >> s1ncetweaks.log
    
    echo Standard mitigations applied.
)

if "%mitigation%"=="2" (
    echo Applying Aggressive Process Mitigation Tweaks...
    echo [Process Mitigations - Aggressive] >> s1ncetweaks.log

    :: Remove all mitigations (maximum performance, lower security)
    powershell -Command "Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*' -Recurse -ErrorAction SilentlyContinue" >> s1ncetweaks.log
    powershell -Command "ForEach($v in (Get-Command -Name 'Set-ProcessMitigation').Parameters['Disable'].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >> s1ncetweaks.log
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222222222222222222" /f >> s1ncetweaks.log
    
    echo Aggressive mitigations applied.
)

if "%mitigation%"=="3" goto PerformanceTweaks

if "%mitigation%" NEQ "3" (
    echo.
    echo Process Mitigation tweaks applied successfully.
    echo.
    echo Press any key to return to Performance Tweaks menu...
    pause >nul
)
goto PerformanceTweaks

:PowerTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║            POWER PLAN OPTIMIZATION             ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Applying Power Optimization Tweaks...
echo [Power Tweaks] >> s1ncetweaks.log

:: Import optimized power plan
powercfg -import "C:\Khorvie.pow" 11111111-1111-1111-1111-111111111111 >> s1ncetweaks.log
powercfg -setactive 11111111-1111-1111-1111-111111111111 >> s1ncetweaks.log

:: Disable hibernation to free up disk space
echo Disabling hibernation...
powercfg -h off >> s1ncetweaks.log

:: Disable PowerThrottling for better performance
echo Disabling PowerThrottling...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >> s1ncetweaks.log

:: Disable Fast Startup (causes issues with some systems)
echo Disabling Fast Startup...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Disable selective suspend
echo Optimizing USB power settings...
for /f "tokens=*" %%i in ('powershell -command "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' } | ForEach-Object { $_.InstanceId }"') do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f 2>nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f 2>nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f 2>nul
    echo Optimized USB device: %%i >> s1ncetweaks.log
)

echo.
echo Power optimization tweaks applied successfully.
echo.
echo Press any key to return to Performance Tweaks menu...
pause >nul
goto PerformanceTweaks

:ServiceTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║             SERVICE OPTIMIZATION               ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [WARNING] Disabling services can improve performance but may affect
echo          certain Windows functionality. Only recommended for gaming PCs.
echo.
echo The following functionality may be affected:
echo - Windows Update
echo - Printing and scanning
echo - Bluetooth devices
echo - Windows Store apps
echo - Hyper-V and virtualization
echo.
echo [1] Disable non-essential services (Recommended)
echo [2] Disable all unnecessary services (Aggressive)
echo [3] Restore default services
echo [4] Back to Performance Menu
echo.
set /p svc=Enter your choice (1-4): 

if "%svc%"=="1" (
    echo Disabling non-essential services...
    echo [Services - Recommended] >> s1ncetweaks.log
    
    for %%a in (
      DiagTrack
      dmwappushservice
      MapsBroker
      lfsvc
      SysMain
      WSearch
      TrkWks
    ) do (
      sc config %%a start= disabled >> s1ncetweaks.log
      sc stop %%a >> s1ncetweaks.log
      echo Disabled service: %%a
    )
    
    echo Non-essential services disabled.
)

if "%svc%"=="2" (
    echo Disabling all unnecessary services...
    echo [Services - Aggressive] >> s1ncetweaks.log
    
    for %%a in (
      DiagTrack
      dmwappushservice
      MapsBroker
      lfsvc
      SysMain
      WSearch
      TrkWks
      BITS
      wuauserv
      DoSvc
      UsoSvc
      bthserv
      BthAvctpSvc
      BluetoothUserService
      Fax
      Spooler
      PrintNotify
      WpcMonSvc
      lltdsvc
      WalletService
      TokenBroker
    ) do (
      sc config %%a start= disabled >> s1ncetweaks.log
      sc stop %%a >> s1ncetweaks.log
      echo Disabled service: %%a
    )
    
    echo All unnecessary services disabled.
)

if "%svc%"=="3" (
    echo Restoring default services...
    echo [Services - Restore Default] >> s1ncetweaks.log
    
    for %%a in (
      DiagTrack
      BITS
      wuauserv
      SysMain
      WSearch
    ) do (
      sc config %%a start= auto >> s1ncetweaks.log
      sc start %%a >> s1ncetweaks.log
      echo Restored service: %%a
    )
    
    for %%a in (
      dmwappushservice
      MapsBroker
      lfsvc
      TrkWks
      DoSvc
      UsoSvc
    ) do (
      sc config %%a start= demand >> s1ncetweaks.log
      echo Restored service: %%a
    )
    
    echo Default services restored.
)

if "%svc%"=="4" goto PerformanceTweaks

if "%svc%" NEQ "4" (
    echo.
    echo Service tweaks applied successfully.
    echo.
    echo Press any key to return to Performance Tweaks menu...
    pause >nul
)
goto PerformanceTweaks

:BootTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║           BOOT CONFIGURATION TWEAKS            ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [WARNING] These tweaks modify your boot configuration.
echo          If you use virtualization features, some options
echo          may affect those features.
echo.
echo [1] Apply Standard Boot Tweaks (Safe)
echo [2] Apply Advanced Boot Tweaks (No Virtualization)
echo [3] Back to Performance Menu
echo.
set /p boot=Enter your choice (1-3): 

if "%boot%"=="1" (
    echo Applying Standard Boot Configuration Tweaks...
    echo [Boot Tweaks - Standard] >> s1ncetweaks.log

    :: Standard Boot Parameters
    bcdedit /deletevalue useplatformclock >> s1ncetweaks.log
    bcdedit /set disabledynamictick yes >> s1ncetweaks.log
    bcdedit /set bootmenupolicy Legacy >> s1ncetweaks.log
    
    echo Standard boot tweaks applied.
)

if "%boot%"=="2" (
    echo Applying Advanced Boot Configuration Tweaks...
    echo [Boot Tweaks - Advanced] >> s1ncetweaks.log

    :: Advanced Boot Parameters - includes disabling virtualization
    bcdedit /deletevalue useplatformclock >> s1ncetweaks.log
    bcdedit /set disableelamdrivers Yes >> s1ncetweaks.log
    bcdedit /set bootmenupolicy Legacy >> s1ncetweaks.log
    bcdedit /set disabledynamictick yes >> s1ncetweaks.log
    bcdedit /set hypervisorlaunchtype Off >> s1ncetweaks.log
    bcdedit /set nx OptIn >> s1ncetweaks.log
    bcdedit /set isolatedcontext No >> s1ncetweaks.log
    
    echo Advanced boot tweaks applied.
)

if "%boot%"=="3" goto PerformanceTweaks

if "%boot%" NEQ "3" (
    echo.
    echo Boot configuration tweaks applied successfully.
    echo.
    echo Press any key to return to Performance Tweaks menu...
    pause >nul
)
goto PerformanceTweaks

:GPUOptimization
cls
echo ╔════════════════════════════════════════════════╗
echo ║             GPU OPTIMIZATION                   ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Detecting GPU...
echo [GPU Optimization] >> s1ncetweaks.log

:: Detect GPU
for /f "tokens=*" %%i in ('wmic path win32_VideoController get name ^| findstr "NVIDIA AMD Intel"') do (
    set "gpu=%%i"
    echo Detected GPU: %%i >> s1ncetweaks.log
)

echo Detected: %gpu%
echo.
echo [1] Apply Generic GPU Optimizations (All GPUs)
echo [2] Optimize for NVIDIA GPUs
echo [3] Optimize for AMD GPUs
echo [4] Optimize for Intel GPUs
echo [5] Back to Performance Menu
echo.
set /p gpuchoice=Enter your choice (1-5): 

if "%gpuchoice%"=="1" (
    echo Applying Generic GPU Optimizations...
    
    :: Windows Graphics Settings
    reg add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;" /f >> s1ncetweaks.log
    
    :: Game Mode and Game Bar Settings
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
    reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
    
    :: DXGI Settings
    reg add "HKLM\SOFTWARE\Microsoft\Graphics Drivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >> s1ncetweaks.log
    
    echo Generic GPU optimizations applied.
)

if "%gpuchoice%"=="2" (
    echo Optimizing for NVIDIA GPUs...
    
    :: NVIDIA-specific registry tweaks
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d "8" /f >> s1ncetweaks.log
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d "8" /f >> s1ncetweaks.log
    
    :: NVIDIA Power Settings
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Graphics\Configs\NVIDIA (*(D3)*(*)) NVIDIA" /v "PowerMizer_Enable" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Graphics\Configs\NVIDIA (*(D3)*(*)) NVIDIA" /v "PowerMizer_Level" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    
    echo NVIDIA optimizations applied.
)

if "%gpuchoice%"=="3" (
    echo Optimizing for AMD GPUs...
    
    :: AMD-specific registry tweaks
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    
    echo AMD optimizations applied.
)

if "%gpuchoice%"=="4" (
    echo Optimizing for Intel GPUs...
    
    :: Intel-specific registry tweaks
    reg add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "512" /f >> s1ncetweaks.log
    
    echo Intel optimizations applied.
)

if "%gpuchoice%"=="5" goto PerformanceTweaks

if "%gpuchoice%" NEQ "5" (
    echo.
    echo GPU optimizations applied successfully.
    echo.
    echo Press any key to return to Performance Tweaks menu...
    pause >nul
)
goto PerformanceTweaks

:AllPerformanceTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║        APPLYING ALL PERFORMANCE TWEAKS         ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [INFO] This will apply all recommended performance tweaks at once.
echo       This process will take a few moments.
echo.
echo Processing...

:: Memory Management
echo Applying Memory Management Tweaks...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Process Priority Control
echo Setting Process Priority Control...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "36" /f >> s1ncetweaks.log

:: System Responsiveness
echo Setting System Responsiveness...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f >> s1ncetweaks.log

:: Service Host threshold based on RAM detection
echo Setting Service Host Split Threshold...
echo ╔════════════════════════════════════════════════╗
echo ║         SERVICE HOST OPTIMIZATION              ║
echo ╚════════════════════════════════════════════════╝
echo.
echo This tweak reduces the number of svchost.exe processes
echo running on your system by setting a higher memory threshold.
echo.
echo Please select your system RAM amount if there is not your ammount pls select the closest to it:
echo.
echo [1] 4 GB RAM
echo [2] 8 GB RAM
echo [3] 16 GB RAM
echo [4] 32 GB RAM
echo [5] 64 GB RAM
echo [6] Skip
echo.
set /p ram=Enter your choice (1-6): 

if "%ram%"=="1" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4194304" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 4 GB RAM.
)
if "%ram%"=="2" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "8388608" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 8 GB RAM.
)
if "%ram%"=="3" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "16777216" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 16 GB RAM.
)
if "%ram%"=="4" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "33554432" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 32 GB RAM.
)
if "%ram%"=="5" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "67108864" /f >> s1ncetweaks.log
    echo Service Host Threshold set for 64 GB RAM.
)

if "%ram%"=="6" (
    echo Skipping 
)

if "%ram%" NEQ "7" (
    echo.
    echo Service Host optimizations applied successfully.
    echo.
)

:: Process and Kernel Mitigations (Standard)
echo Disabling Process Mitigations...
powershell -Command "Set-ProcessMitigation -System -Disable CFG, ForceRelocateImages, RequireInfo, BottomUp, HighEntropy" >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222222222222222222" /f >> s1ncetweaks.log

:: Import optimized power plan and disable hibernation
echo Optimizing Power Settings...
powercfg -import "C:\Khorvie.pow" 11111111-1111-1111-1111-111111111111 >> s1ncetweaks.log
powercfg -setactive 11111111-1111-1111-1111-111111111111 >> s1ncetweaks.log
powercfg -h off >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Disable USB power savings
echo Optimizing USB power settings...
for /f "tokens=*" %%i in ('powershell -command "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' } | ForEach-Object { $_.InstanceId }"') do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f 2>nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f 2>nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f 2>nul
)

:: Disable Non-essential services
echo Disabling Non-essential Services...
for %%a in (
  DiagTrack
  dmwappushservice
  MapsBroker
  lfsvc
  SysMain
  WSearch
  TrkWks
) do (
  sc config %%a start= disabled >> s1ncetweaks.log
  sc stop %%a >> s1ncetweaks.log
)

:: Boot Parameters
echo Applying Boot Parameters...
bcdedit /deletevalue useplatformclock >> s1ncetweaks.log
bcdedit /set disabledynamictick yes >> s1ncetweaks.log
bcdedit /set bootmenupolicy Legacy >> s1ncetweaks.log

:: Quality of Life Tweaks
echo Applying Quality of Life Tweaks...
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f >> s1ncetweaks.log

:: GPU Optimizations (Generic)
echo Applying Generic GPU Optimizations...
reg add "HKCU\SOFTWARE\Microsoft\DirectX\UserGpuPreferences" /v "DirectXUserGlobalSettings" /t REG_SZ /d "VRROptimizeEnable=0;" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Graphics Drivers" /v "HwSchMode" /t REG_DWORD /d "2" /f >> s1ncetweaks.log

echo.
echo All performance tweaks have been applied successfully!
echo.
echo Press any key to return to Performance Tweaks menu...
pause >nul
goto PerformanceTweaks

:PrivacyTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║              PRIVACY TWEAKS                    ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [1] Disable Telemetry and Data Collection
echo [2] Disable Windows Error Reporting
echo [3] Disable Windows Defender (Not Recommended)
echo [4] Run OO ShutUp10 (Advanced Privacy Settings)
echo [5] All Privacy Tweaks
echo [6] Back to Main Menu
echo.
set /p privchoice=Enter your choice (1-6): 
if "%privchoice%"=="1" goto TelemetryTweaks
if "%privchoice%"=="2" goto ErrorReportingTweaks
if "%privchoice%"=="3" goto DefenderMenu
if "%privchoice%"=="4" goto OOSU10
if "%privchoice%"=="5" goto AllPrivacyTweaks
if "%privchoice%"=="6" goto MainMenu

echo Invalid option. Please try again.
timeout /t 2 /nobreak >nul
goto PrivacyTweaks

:TelemetryTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║       TELEMETRY AND DATA COLLECTION            ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Disabling Telemetry and Data Collection...
echo [Telemetry Tweaks] >> s1ncetweaks.log

:: Disable Telemetry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Disable additional telemetry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Disable DiagTrack service
sc config DiagTrack start= disabled >> s1ncetweaks.log
sc stop DiagTrack >> s1ncetweaks.log
sc config dmwappushservice start= disabled >> s1ncetweaks.log
sc stop dmwappushservice >> s1ncetweaks.log

echo.
echo Telemetry and data collection have been disabled.
echo.
echo Press any key to return to Privacy Tweaks menu...
pause >nul
goto PrivacyTweaks

:ErrorReportingTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║         WINDOWS ERROR REPORTING                ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Disabling Windows Error Reporting...
echo [Error Reporting Tweaks] >> s1ncetweaks.log

:: Disable Error Reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\WerKernelReporting" /v "DisableKernelReporting" /t REG_DWORD /d "1" /f >> s1ncetweaks.log

:: Disable WER Service
sc config WerSvc start= disabled >> s1ncetweaks.log
sc stop WerSvc >> s1ncetweaks.log

echo.
echo Windows Error Reporting has been disabled.
echo.
echo Press any key to return to Privacy Tweaks menu...
pause >nul
goto PrivacyTweaks

:DefenderMenu
cls
echo ╔════════════════════════════════════════════════╗
echo ║            WINDOWS DEFENDER                    ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [WARNING] Disabling Windows Defender reduces your protection
echo          against malware and is NOT RECOMMENDED unless you
echo          have alternative security software installed.
echo.
echo [1] Disable Windows Defender (Not Recommended)
echo [2] Optimize Windows Defender (Better Performance)
echo [3] Re-enable Windows Defender
echo [4] Back to Privacy Tweaks
echo.
set /p def=Enter your choice (1-4): 

if "%def%"=="1" (
    echo Disabling Windows Defender...
    echo [Windows Defender - Disabled] >> s1ncetweaks.log
    
    :: Disable Windows Defender through registry
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    
    :: Disable services
    sc config WinDefend start= disabled >> s1ncetweaks.log
    sc stop WinDefend >> s1ncetweaks.log
    sc config WdNisSvc start= disabled >> s1ncetweaks.log
    sc stop WdNisSvc >> s1ncetweaks.log
    sc config Sense start= disabled >> s1ncetweaks.log
    sc stop Sense >> s1ncetweaks.log
    
    echo Windows Defender has been disabled.
    echo [WARNING] Your system is now more vulnerable to malware.
    echo Consider installing an alternative security solution.
)

if "%def%"=="2" (
    echo Optimizing Windows Defender...
    echo [Windows Defender - Optimized] >> s1ncetweaks.log
    
    :: Optimize Windows Defender without disabling it
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
    
    :: Add exclusion for games folder
    powershell -Command "Add-MpPreference -ExclusionPath 'C:\Program Files (x86)\Steam'" >> s1ncetweaks.log
    powershell -Command "Add-MpPreference -ExclusionPath 'C:\Program Files\Epic Games'" >> s1ncetweaks.log
    
    echo Windows Defender has been optimized for better performance
    echo while maintaining essential protection.
)

if "%def%"=="3" (
    echo Re-enabling Windows Defender...
    echo [Windows Defender - Enabled] >> s1ncetweaks.log
    
    :: Re-enable Windows Defender
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >> s1ncetweaks.log 2>nul
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /f >> s1ncetweaks.log 2>nul
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /f >> s1ncetweaks.log 2>nul
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /f >> s1ncetweaks.log 2>nul
    
    :: Re-enable services
    sc config WinDefend start= auto >> s1ncetweaks.log
    sc start WinDefend >> s1ncetweaks.log
    sc config WdNisSvc start= auto >> s1ncetweaks.log
    sc start WdNisSvc >> s1ncetweaks.log
    
    echo Windows Defender has been re-enabled.
)

if "%def%"=="4" goto PrivacyTweaks

if "%def%" NEQ "4" (
    echo.
    echo Windows Defender settings have been updated.
    echo.
    echo Press any key to return to Privacy Tweaks menu...
    pause >nul
)
goto PrivacyTweaks

:OOSU10
cls
echo ╔════════════════════════════════════════════════╗
echo ║               OO SHUTUP10                      ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Running OO ShutUp10 with recommended settings...
echo [OO ShutUp10] >> s1ncetweaks.log

start "" /wait "%s1nce%\OOSU10.exe" "%s1nce%\ooshutup10.cfg" /quiet

echo.
echo OO ShutUp10 privacy settings have been applied.
echo.
echo Press any key to return to Privacy Tweaks menu...
pause >nul
goto PrivacyTweaks

:AllPrivacyTweaks
cls
echo ╔════════════════════════════════════════════════╗
echo ║         APPLYING ALL PRIVACY TWEAKS            ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [INFO] This will apply all recommended privacy tweaks at once.
echo       This process will take a few moments.
echo.
echo Processing...

:: Telemetry and Data Collection
echo Disabling Telemetry and Data Collection...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Error Reporting
echo Disabling Windows Error Reporting...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
sc config WerSvc start= disabled >> s1ncetweaks.log
sc stop WerSvc >> s1ncetweaks.log

:: Defender Optimization (not disabling)
echo Optimizing Windows Defender...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f >> s1ncetweaks.log
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f >> s1ncetweaks.log

:: Disable diagnostic services
echo Disabling Diagnostic Services...
sc config DiagTrack start= disabled >> s1ncetweaks.log
sc stop DiagTrack >> s1ncetweaks.log
sc config dmwappushservice start= disabled >> s1ncetweaks.log
sc stop dmwappushservice >> s1ncetweaks.log

:: Run O&O ShutUp10
echo Running OO ShutUp10...
start "" /wait "%s1nce%\OOSU10.exe" "%s1nce%\ooshutup10.cfg" /quiet

echo.
echo All privacy tweaks have been applied successfully!
echo.
echo Press any key to return to Privacy Tweaks menu...

:VisualSettings
cls
echo ╔════════════════════════════════════════════════╗
echo ║              VISUAL SETTINGS                   ║
echo ╚════════════════════════════════════════════════╝
echo.
echo [1] Performance Visual Settings
echo [2] Disable Transparency Effects
echo [3] Disable Animations and Effects
echo [4] Enable Dark Mode
echo [5] Apply All Visual Tweaks
echo [6] Back to Main Menu
echo.
set /p vischoice=Enter your choice (1-6): 
if "%vischoice%"=="1" goto PerformanceVisual
if "%vischoice%"=="2" goto TransparencyEffects
if "%vischoice%"=="3" goto AnimationEffects
if "%vischoice%"=="4" goto DarkMode
if "%vischoice%"=="5" goto AllVisualTweaks
if "%vischoice%"=="6" goto MainMenu

echo Invalid option. Please try again.
timeout /t 2 /nobreak >nul
goto VisualSettings

:PerformanceVisual
cls
echo Applying Performance Visual Settings...
echo [Performance Visual Settings] >> s1ncetweaks.log

:: Set visual effects for performance
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

echo Performance Visual Settings applied successfully!
echo Operation completed at %time% on %date% >> s1ncetweaks.log
timeout /t 3 /nobreak >nul
goto VisualSettings

:TransparencyEffects
cls
echo Disabling Transparency Effects...
echo [Transparency Effects Disabled] >> s1ncetweaks.log

:: Disable transparency
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f >> s1ncetweaks.log

echo Transparency Effects have been disabled!
echo Operation completed at %time% on %date% >> s1ncetweaks.log
timeout /t 3 /nobreak >nul
goto VisualSettings

:AnimationEffects
cls
echo Disabling Animations and Effects...
echo [Animations and Effects Disabled] >> s1ncetweaks.log

:: Disable animations
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAnimations" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Disable fading effects
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "0" /f >> s1ncetweaks.log

echo Animations and Effects have been disabled!
echo Operation completed at %time% on %date% >> s1ncetweaks.log
timeout /t 3 /nobreak >nul
goto VisualSettings

:DarkMode
cls
echo Enabling Dark Mode...
echo [Dark Mode Enabled] >> s1ncetweaks.log

:: Enable dark mode
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

echo Dark Mode has been enabled!
echo Operation completed at %time% on %date% >> s1ncetweaks.log
timeout /t 3 /nobreak >nul
goto VisualSettings

:AllVisualTweaks
cls
echo Applying All Visual Tweaks...
echo [All Visual Tweaks Applied] >> s1ncetweaks.log

:: Set visual effects for performance
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "2" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Disable transparency
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f >> s1ncetweaks.log

:: Disable animations
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAnimations" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

:: Disable fading effects
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "0" /f >> s1ncetweaks.log

:: Enable dark mode
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f >> s1ncetweaks.log
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f >> s1ncetweaks.log

echo All Visual Tweaks have been applied successfully!
echo Operation completed at %time% on %date% >> s1ncetweaks.log
timeout /t 3 /nobreak >nul
goto MainMenu

:networkoptimization
cls
echo ╔════════════════════════════════════════════════╗
echo ║           Network Optimization                 ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Applying network tweaks...
echo.

:: Reset TCP/IP stack
echo Resetting TCP/IP stack...
netsh int ip reset
netsh winsock reset

:: Set DNS Flush
echo Flushing DNS cache...
ipconfig /flushdns

:: Network Adapter Optimization
echo Optimizing network adapters...
powershell -Command "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-NetTCPSetting -SettingName CustomSettings -AutoTuningLevelLocal Normal -ScalingHeuristics Disabled }"

:: Disabling Nagle's Algorithm (can reduce latency for some applications)
echo Disabling Nagle's Algorithm...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f

:: Optimize Internet Settings
echo Optimizing Internet Settings...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "0xffffffff" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f

:: Enable gaming mode for networking (reduces latency)
echo Enabling gaming network mode...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f

echo Network optimization complete!
timeout /t 3 >nul
goto MainMenu

:exit
cls
echo ╔════════════════════════════════════════════════╗
echo ║               Exiting S1NCE TWEAKS             ║
echo ╚════════════════════════════════════════════════╝
echo.
echo Thank you for using S1NCE TWEAKS!
echo.
echo Exiting in 3 seconds...
timeout /t 3 >nul
exit
