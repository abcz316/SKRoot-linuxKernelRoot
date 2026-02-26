@echo off
set "ndk_path=c:\Users\abc\android-ndk-r26d\ndk-build.cmd"

cd /d "%~dp0"

set "root_path=%~dp0"

cd %root_path%
call clean_lib.bat

if not exist %ndk_path% (
    echo Error:  Android NDK: '%ndk_path%' does not exist!
    pause
    exit /b
)

cd %root_path%\src\jni\lib_su_env\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %root_path%\src\jni\lib_su_env
call generate_source_lib_su_env_data.bat

cd %root_path%\src\jni
call "%ndk_path%" clean
call "%ndk_path%" -j8
mkdir %root_path%\lib
move /Y %root_path%\src\obj\local\arm64-v8a\libkernel_root_kit_static.a %root_path%\lib\

cd %root_path%\src\jni\su\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %root_path%\src\jni\su
call generate_source_su_exec_data.bat

cd %root_path%\src\jni
call "%ndk_path%" clean
call "%ndk_path%" -j8
move /Y %root_path%\src\obj\local\arm64-v8a\libkernel_root_kit_static.a %root_path%\lib\

cd %root_path%\src\jni\web_server
call generate_source_web_server_html_data.bat
cd %root_path%\src\jni\web_server\jni
call "%ndk_path%" clean
call "%ndk_path%"
cd %root_path%\src\jni\web_server
call generate_source_web_server_exec_data.bat

cd %root_path%\src\jni
call "%ndk_path%" clean
call "%ndk_path%" -j8
move /Y %root_path%\src\obj\local\arm64-v8a\libkernel_root_kit_static.a %root_path%\lib\


cd %root_path%\src\jni\lib_web_server_loader\jni
call "%ndk_path%" clean
call "%ndk_path%"
cd %root_path%\src\jni\lib_web_server_loader
call generate_source_lib_web_server_loader_data.bat

cd %root_path%\src\jni
call "%ndk_path%" clean
call "%ndk_path%" -j8
move /Y %root_path%\src\obj\local\arm64-v8a\libkernel_root_kit_static.a %root_path%\lib\

echo All builds completed!
pause
