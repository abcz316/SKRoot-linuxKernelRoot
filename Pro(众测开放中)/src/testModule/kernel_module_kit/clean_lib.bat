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

if exist "src\jni\skroot_env\su\su_data.generated.h" (
    del "src\jni\skroot_env\su\su_data.generated.h"
)

if exist "src\jni\skroot_env\su\libs" (
    rmdir /S /Q "src\jni\skroot_env\su\libs"
)

if exist "src\jni\skroot_env\su\obj" (
    rmdir /S /Q "src\jni\skroot_env\su\obj"
)


if exist "src\jni\skroot_env\features\webui_loader\res.h" (
    del "src\jni\skroot_env\features\webui_loader\res.h"
)

if exist "src\jni\skroot_env\features\webui_loader\webui_loader_data.generated.h" (
    del "src\jni\skroot_env\features\webui_loader\webui_loader_data.generated.h"
)

if exist "src\jni\skroot_env\features\webui_loader\libs" (
    rmdir /S /Q "src\jni\skroot_env\features\webui_loader\libs"
)

if exist "src\jni\skroot_env\features\webui_loader\obj" (
    rmdir /S /Q "src\jni\skroot_env\features\webui_loader\obj"
)

if exist "src\jni\skroot_env\autorun_bootstrap\res.h" (
    del "src\jni\skroot_env\autorun_bootstrap\res.h"
)

if exist "src\jni\skroot_env\autorun_bootstrap\autorun_bootstrap_file_data.generated.h" (
    del "src\jni\skroot_env\autorun_bootstrap\autorun_bootstrap_file_data.generated.h"
)

if exist "src\jni\skroot_env\autorun_bootstrap\libs" (
    rmdir /S /Q "src\jni\skroot_env\autorun_bootstrap\libs"
)

if exist "src\jni\skroot_env\autorun_bootstrap\obj" (
    rmdir /S /Q "src\jni\skroot_env\autorun_bootstrap\obj"
)

if exist "src\jni\skroot_env\parasite_app\parasite_web_server\res.h" (
    del "src\jni\skroot_env\parasite_app\parasite_web_server\res.h"
)

if exist "src\jni\skroot_env\parasite_app\parasite_web_server\parasite_web_server_file_data.generated.h" (
    del "src\jni\skroot_env\parasite_app\parasite_web_server\parasite_web_server_file_data.generated.h"
)

if exist "src\jni\skroot_env\parasite_app\parasite_web_server\libs" (
    rmdir /S /Q "src\jni\skroot_env\parasite_app\parasite_web_server\libs"
)

if exist "src\jni\skroot_env\parasite_app\parasite_web_server\obj" (
    rmdir /S /Q "src\jni\skroot_env\parasite_app\parasite_web_server\obj"
) 

if exist "src\jni\skroot_env\parasite_app\parasite_web_server\index.gz.bin" (
    del "src\jni\skroot_env\parasite_app\parasite_web_server\index.gz.bin"
)

if exist "src\jni\skroot_env\parasite_app\parasite_web_server\index_html_gz_data.generated.h" (
    del "src\jni\skroot_env\parasite_app\parasite_web_server\index_html_gz_data.generated.h"
)

if exist "src\jni\skroot_env\parasite_app\parasite_web_server\app_label_helper_data.generated.h" (
    del "src\jni\skroot_env\parasite_app\parasite_web_server\app_label_helper_data.generated.h"
)

if exist "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\lib_parasite_web_server_loader_data.generated.h" (
    del "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\lib_parasite_web_server_loader_data.generated.h"
)

if exist "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\res.h" (
    del "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\res.h"
)

if exist "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\libs" (
    rmdir /S /Q "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\libs"
)

if exist "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\obj" (
    rmdir /S /Q "src\jni\skroot_env\parasite_app\lib_parasite_web_server_loader\obj"
) 
