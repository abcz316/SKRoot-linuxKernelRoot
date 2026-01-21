@echo off
cd /d "%~dp0"

if exist "src\obj" (
    rmdir /S /Q "src\obj"
)

if exist "lib" (
    rmdir /S /Q "lib"
)

if exist "src\jni\skroot_env\su\res.h" (
    del "src\jni\skroot_env\su\res.h"
)

if exist "src\jni\skroot_env\su\su_exec_data.h" (
    del "src\jni\skroot_env\su\su_exec_data.h"
)

if exist "src\jni\skroot_env\su\libs" (
    rmdir /S /Q "src\jni\skroot_env\su\libs"
)

if exist "src\jni\skroot_env\su\obj" (
    rmdir /S /Q "src\jni\skroot_env\su\obj"
)


if exist "src\jni\skroot_env\features\weui_loader\res.h" (
    del "src\jni\skroot_env\features\weui_loader\res.h"
)

if exist "src\jni\skroot_env\features\weui_loader\weui_loader_exec_data.h" (
    del "src\jni\skroot_env\features\weui_loader\weui_loader_exec_data.h"
)

if exist "src\jni\skroot_env\features\weui_loader\libs" (
    rmdir /S /Q "src\jni\skroot_env\features\weui_loader\libs"
)

if exist "src\jni\skroot_env\features\weui_loader\obj" (
    rmdir /S /Q "src\jni\skroot_env\features\weui_loader\obj"
)

if exist "src\jni\skroot_env\autorun_bootstrap\res.h" (
    del "src\jni\skroot_env\autorun_bootstrap\res.h"
)

if exist "src\jni\skroot_env\autorun_bootstrap\autorun_bootstrap_file_data.h" (
    del "src\jni\skroot_env\autorun_bootstrap\autorun_bootstrap_file_data.h"
)

if exist "src\jni\skroot_env\autorun_bootstrap\libs" (
    rmdir /S /Q "src\jni\skroot_env\autorun_bootstrap\libs"
)

if exist "src\jni\skroot_env\autorun_bootstrap\obj" (
    rmdir /S /Q "src\jni\skroot_env\autorun_bootstrap\obj"
) 

