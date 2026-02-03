@echo off
set "ndk_path=c:\Users\abc\android-ndk-r26d\ndk-build.cmd"

cd /d "%~dp0"

set "module_path=%~dp0"

cd %module_path%
call clean_lib.bat

if not exist %ndk_path% (
    echo Error:  Android NDK: '%ndk_path%' does not exist!
    pause
    exit /b
)

cd %module_path%\src\jni
call "%ndk_path%" clean
call "%ndk_path%" -j16
mkdir %module_path%\lib
move /Y %module_path%\src\obj\local\arm64-v8a\libkernel_module_kit_static.a %module_path%\lib\

cd %module_path%\src\jni\skroot_env\su\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %module_path%\src\jni\skroot_env\su
call generate_source_su_exec_data.bat

cd %module_path%\src\jni\skroot_env\features\webui_loader\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %module_path%\src\jni\skroot_env\features\webui_loader
call generate_source_webui_loader_exec_data.bat

cd %module_path%\src\jni\skroot_env\autorun_bootstrap\jni
call "%ndk_path%" clean
call "%ndk_path%"

cd %module_path%\src\jni\skroot_env\autorun_bootstrap
call generate_source_autorun_bootstrap_data.bat

cd %module_path%\src\jni
call "%ndk_path%" clean
call "%ndk_path%" -j16
move /Y %module_path%\src\obj\local\arm64-v8a\libkernel_module_kit_static.a %module_path%\lib\

echo All builds completed!
pause
