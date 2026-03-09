@echo off
cd /d "%~dp0"

set "work_path=%~dp0"
set "kernel_root_path=%~dp0../../../../kernel_root_kit/src/jni"

echo %work_path%
echo %kernel_root_path%

if not exist %work_path%/index.html (
    echo Error: '%work_path%index.html' does not exist!
    pause
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%kernel_root_path%/common/file_to_gzip.ps1" -InFile "%work_path%/index.html"

powershell -ExecutionPolicy Bypass -File "%kernel_root_path%/common/file_convert_to_source_tools.ps1" -InFile "%work_path%/index.gz.bin"

:: 将res.h文件中的文本进行替换
powershell -Command "(Get-Content res.h) -replace 'namespace {', 'namespace web_server {' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'fileSize', 'index_html_gz_size' | Set-Content res.h"
powershell -Command "(Get-Content res.h) -replace 'data', 'index_html_gz_data' | Set-Content res.h"

:: 将临时文件重命名为最终的文件名
move /Y res.h index_html_gz_data.generated.h

if exist res.h (
    del res.h
)

if exist index.gz.bin (
    del index.gz.bin
)
echo Finished generating the 'index_html_gz_data.generated.h' file!

