@echo off
cd /d "%~dp0"

set "work_path=%~dp0"
set "kernel_root_path=%~dp0../../../../kernel_root_kit/src/jni"

echo %work_path%
echo %kernel_root_path%

if not exist %work_path%libs/arm64-v8a/web_server (
    echo Error: '%work_path%libs/arm64-v8a/web_server' does not exist!
    pause
    exit /b
)

powershell -ExecutionPolicy Bypass -File "%kernel_root_path%/common/file_convert_to_source_tools.ps1" -InFile "%work_path%/libs/arm64-v8a/web_server"

:: 将res.h文件中的文本进行替换
powershell -Command "(Get-Content res.h) -replace 'namespace {', 'namespace kernel_root {' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'fileSize', 'web_server_file_size' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'data', 'web_server_file_data' | Set-Content res.h"

powershell -NoProfile -Command "$ins='#endif'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#define WEB_SERVER_DATA 1'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#ifndef WEB_SERVER_DATA'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#include <stdint.h>'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"
powershell -NoProfile -Command "$ins='#pragma once'; $old=Get-Content 'res.h'; @($ins)+$old | Set-Content -Encoding UTF8 'res.h'"

:: 将临时文件重命名为最终的文件名
move /Y res.h web_server_data.generated.h

if exist res.h (
    del res.h
)

if exist "%work_path%\libs" (
    rmdir /S /Q "%work_path%\libs"
)

if exist "%work_path%\obj" (
    rmdir /S /Q "%work_path%\obj"
)

echo Finished generating the 'web_server_data.generated.h' file!
