@echo off
chcp 65001

:: 检查文件是否存在
if not exist ../libs/arm64-v8a/su (
    echo Error: '../libs/arm64-v8a/su' does not exist!
    pause
    exit /b
)

:: 使用 echo 和管道(|) 来模拟按下回车键的操作
echo.|"kernel_root_kit/file_convert_to_source_tools/file_convert_to_source_tools.exe" ../libs/arm64-v8a/su

:: 确保上面的命令执行成功，再进行以下的文件替换操作
if %errorlevel% neq 0 (
    echo Error: 'file_convert_to_source_tools.exe' execution failed!
    pause
    exit /b
)

:: 将res.h文件中的文本进行替换
powershell -Command "(Get-Content res.h) -replace 'namespace {', 'namespace kernel_root {' | Set-Content res_temp.h"
powershell -Command "(Get-Content res_temp.h) -replace 'fileSize', 'su_exec_file_size' | Set-Content res_temp2.h"
powershell -Command "(Get-Content res_temp2.h) -replace 'data', 'su_exec_data' | Set-Content res_temp3.h"

:: 将临时文件重命名为最终的文件名
move /Y res_temp3.h kernel_root_kit_su_exec_data.h

:: 删除其他临时文件
del res.h
del res_temp.h
del res_temp2.h

echo Finished generating the 'kernel_root_kit_su_exec_data.h' file!
move /Y kernel_root_kit_su_exec_data.h ./kernel_root_kit
echo Successfully moved file 'kernel_root_kit_su_exec_data.h'!
pause
