@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

REM =====================================================================
REM 程序自动下载脚本 v1.0
REM 功能: 从云端下载加密程序文件
REM =====================================================================

title 程序下载器

echo.
echo ====================================================================
echo                        程序自动下载工具
echo ====================================================================
echo.

REM ===== 配置区域 - 请根据实际情况修改 =====
REM 云盘直链地址(需要替换成实际的直链)
set "DOWNLOAD_URL=https://your-cloud-storage-url.com/your-encrypted-file.dat"

REM 下载后的文件名
set "OUTPUT_FILE=program_encrypted.dat"

REM 启动器程序名
set "LAUNCHER_FILE=launcher.exe"
REM ===== 配置区域结束 =====

echo [1/4] 检测下载工具...
echo.

REM 检测系统中可用的下载工具
set "DOWNLOAD_TOOL="

REM 优先使用 curl
curl --version >nul 2>&1
if %errorlevel% equ 0 (
    set "DOWNLOAD_TOOL=curl"
    echo [✓] 检测到 curl 工具
    goto :download
)

REM 尝试使用 PowerShell
powershell -Command "Get-Command Invoke-WebRequest" >nul 2>&1
if %errorlevel% equ 0 (
    set "DOWNLOAD_TOOL=powershell"
    echo [✓] 检测到 PowerShell 下载功能
    goto :download
)

REM 尝试使用 wget
wget --version >nul 2>&1
if %errorlevel% equ 0 (
    set "DOWNLOAD_TOOL=wget"
    echo [✓] 检测到 wget 工具
    goto :download
)

REM 没有找到任何下载工具
echo [✗] 错误: 未找到可用的下载工具
echo.
echo 请确保系统中安装了以下工具之一:
echo   - curl (Windows 10 1803+ 自带)
echo   - PowerShell (Windows 7+ 自带)
echo   - wget
echo.
goto :error_exit

:download
echo.
echo [2/4] 开始下载文件...
echo.
echo 下载地址: %DOWNLOAD_URL%
echo 保存为: %OUTPUT_FILE%
echo.

REM 检查文件是否已存在
if exist "%OUTPUT_FILE%" (
    echo [!] 警告: 文件 %OUTPUT_FILE% 已存在
    set /p "overwrite=是否覆盖? (Y/N): "
    if /i not "!overwrite!"=="Y" (
        echo [!] 取消下载
        goto :check_launcher
    )
    echo [*] 删除旧文件...
    del "%OUTPUT_FILE%"
)

REM 根据工具类型执行下载
if "%DOWNLOAD_TOOL%"=="curl" (
    echo [*] 使用 curl 下载...
    curl -L --progress-bar -o "%OUTPUT_FILE%" "%DOWNLOAD_URL%"
    set "download_result=!errorlevel!"
) else if "%DOWNLOAD_TOOL%"=="powershell" (
    echo [*] 使用 PowerShell 下载...
    powershell -Command "& {$ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%OUTPUT_FILE%'; exit $LASTEXITCODE}"
    set "download_result=!errorlevel!"
) else if "%DOWNLOAD_TOOL%"=="wget" (
    echo [*] 使用 wget 下载...
    wget -O "%OUTPUT_FILE%" "%DOWNLOAD_URL%"
    set "download_result=!errorlevel!"
)

REM 检查下载结果
if not !download_result! equ 0 (
    echo.
    echo [✗] 下载失败! 错误代码: !download_result!
    echo.
    echo 可能的原因:
    echo   1. 网络连接问题
    echo   2. 下载链接已失效
    echo   3. 云盘访问权限不足
    echo.
    goto :error_exit
)

REM 验证文件是否下载成功
if not exist "%OUTPUT_FILE%" (
    echo [✗] 下载失败: 文件不存在
    goto :error_exit
)

REM 检查文件大小
for %%F in ("%OUTPUT_FILE%") do set "file_size=%%~zF"
if %file_size% lss 1024 (
    echo [✗] 下载失败: 文件大小异常 (%file_size% 字节^)
    echo.
    echo 文件内容预览:
    type "%OUTPUT_FILE%"
    echo.
    goto :error_exit
)

echo.
echo [✓] 下载成功! 文件大小: %file_size% 字节
echo.

:check_launcher
echo [3/4] 检查启动器...
echo.

if not exist "%LAUNCHER_FILE%" (
    echo [✗] 错误: 未找到启动器程序 %LAUNCHER_FILE%
    echo.
    echo 请确保以下文件在同一目录:
    echo   - %~nx0 (本脚本)
    echo   - %LAUNCHER_FILE% (启动器)
    echo   - %OUTPUT_FILE% (加密程序)
    echo.
    goto :error_exit
)

echo [✓] 启动器就绪
echo.

echo [4/4] 准备启动程序...
echo.
echo ====================================================================
echo [✓] 所有准备工作已完成!
echo ====================================================================
echo.
echo 下一步操作:
echo   1. 运行 %LAUNCHER_FILE% 启动程序
echo   2. 输入您的64位激活密钥
echo   3. 验证通过后程序将自动运行
echo.

REM 询问是否立即启动
set /p "start_now=是否现在启动程序? (Y/N): "
if /i "!start_now!"=="Y" (
    echo.
    echo [*] 正在启动 %LAUNCHER_FILE%...
    start "" "%LAUNCHER_FILE%"
    timeout /t 2 >nul
    exit /b 0
)

echo.
echo [*] 您可以稍后手动运行 %LAUNCHER_FILE% 启动程序
echo.
goto :normal_exit

:error_exit
echo.
echo ====================================================================
echo [✗] 操作失败
echo ====================================================================
echo.
echo 如需帮助，请联系技术支持
echo.
pause
exit /b 1

:normal_exit
pause
exit /b 0
