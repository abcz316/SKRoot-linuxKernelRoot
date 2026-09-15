@echo off
setlocal

REM ============================================================
REM  AppLabelsHelper build script
REM  Flow: .java -> (javac) .class -> (d8) classes.dex
REM  Usage: build.bat
REM ============================================================

REM ---------- Config (edit if needed) ----------
set "SDK=C:\Users\abc\AppData\Local\Android\Sdk"
set "PLATFORM=android-33"
set "BUILD_TOOLS=33.0.0"
set "JAVA_HOME=C:\Program Files\Android\Android Studio\jre"

REM ---------- Auto detect ----------
set "ANDROID_JAR=%SDK%\platforms\%PLATFORM%\android.jar"
set "D8_JAR=%SDK%\build-tools\%BUILD_TOOLS%\lib\d8.jar"
set "JAVAC=%JAVA_HOME%\bin\javac.exe"
set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"

if not exist "%ANDROID_JAR%" (
    echo [ERROR] android.jar not found: %ANDROID_JAR%
    exit /b 1
)
if not exist "%D8_JAR%" (
    echo [ERROR] d8.jar not found: %D8_JAR%
    exit /b 1
)
if not exist "%JAVAC%" (
    echo [ERROR] javac.exe not found: %JAVAC%
    echo         Please fix JAVA_HOME at the top of this script.
    exit /b 1
)
if not exist "%JAVA_EXE%" (
    echo [ERROR] java.exe not found: %JAVA_EXE%
    exit /b 1
)

REM ---------- Clean & create output dir ----------
set "OUT=build"
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"

REM ---------- 1. Compile ----------
echo [1/2] javac compiling AppLabelsHelper.java ...
"%JAVAC%" -source 8 -target 8 -encoding UTF-8 -classpath "%ANDROID_JAR%" -d "%OUT%" AppLabelsHelper.java
if errorlevel 1 (
    echo [ERROR] compile failed
    exit /b 1
)

REM ---------- 2. Dex ----------
echo [2/2] d8 generating classes.dex ...
"%JAVA_EXE%" -Xmx1024M -cp "%D8_JAR%" com.android.tools.r8.D8 --output "%OUT%" --lib "%ANDROID_JAR%" "%OUT%\AppLabelsHelper.class"
if errorlevel 1 (
    echo [ERROR] dex failed
    exit /b 1
)

echo.
echo [OK] Done: %OUT%\classes.dex

endlocal
