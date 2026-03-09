@echo off
cd /d "%~dp0"

set "root_path=%~dp0"

if exist "%root_path%src\jni\web_server\web_server_data.generated.h" (
    del "%root_path%src\jni\web_server\web_server_data.generated.h"
)

if exist "%root_path%src\jni\lib_web_server_loader\lib_web_server_loader_data.generated.h" (
    del "%root_path%src\jni\lib_web_server_loader\lib_web_server_loader_data.generated.h"
)

if exist "%root_path%src\jni\su\su_data.generated.h" (
    del "%root_path%src\jni\su\su_data.generated.h"
)

if exist "%root_path%src\jni\lib_su_env\lib_su_env_data.generated.h" (
    del "%root_path%src\jni\lib_su_env\lib_su_env_data.generated.h"
)

if exist "%root_path%src\jni\lib_web_server_loader\res.h" (
    del "%root_path%src\jni\lib_web_server_loader\res.h"
)

if exist "%root_path%src\jni\web_server\res.h" (
    del "%root_path%src\jni\web_server\res.h"
)

if exist "%root_path%src\jni\su\res.h" (
    del "%root_path%src\jni\su\res.h"
)

if exist "%root_path%src\jni\lib_su_env\res.h" (
    del "%root_path%src\jni\lib_su_env\res.h"
)

if exist "%root_path%src\jni\lib_web_server_loader\index.gz.bin" (
    del "%root_path%src\jni\lib_web_server_loader\index.gz.bin"
)

if exist "%root_path%src\jni\lib_web_server_loader\index_html_gz_data.generated.h" (
    del "%root_path%src\jni\lib_web_server_loader\index_html_gz_data.generated.h"
)

if exist "%root_path%src\jni\web_server\index.gz.bin" (
    del "%root_path%src\jni\web_server\index.gz.bin"
)

if exist "%root_path%src\jni\web_server\index_html_gz_data.generated.h" (
    del "%root_path%src\jni\web_server\index_html_gz_data.generated.h"
)


if exist "%root_path%\src\obj" (
    rmdir /S /Q "%root_path%\src\obj"
)

if exist "%root_path%\lib" (
    rmdir /S /Q "%root_path%\lib"
)

if exist "%root_path%\src\jni\su\libs" (
    rmdir /S /Q "%root_path%\src\jni\su\libs"
)

if exist "%root_path%\src\jni\su\obj" (
    rmdir /S /Q "%root_path%\src\jni\su\obj"
) 

if exist "%root_path%\src\jni\lib_su_env\libs" (
    rmdir /S /Q "%root_path%\src\jni\lib_su_env\libs"
)

if exist "%root_path%\src\jni\lib_su_env\obj" (
    rmdir /S /Q "%root_path%\src\jni\lib_su_env\obj"
) 

if exist "%root_path%\src\jni\lib_web_server_loader\libs" (
    rmdir /S /Q "%root_path%\src\jni\lib_web_server_loader\libs"
)

if exist "%root_path%\src\jni\lib_web_server_loader\obj" (
    rmdir /S /Q "%root_path%\src\jni\lib_web_server_loader\obj"
) 

if exist "%root_path%\src\jni\web_server\libs" (
    rmdir /S /Q "%root_path%\src\jni\web_server\libs"
)

if exist "%root_path%\src\jni\web_server\obj" (
    rmdir /S /Q "%root_path%\src\jni\web_server\obj"
) 
