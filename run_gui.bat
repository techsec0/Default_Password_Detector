@echo off
cd /d %~dp0

:: === JavaFX SDK lib path ===
set FX_LIB=lib\javafx-sdk-24.0.2\lib

:: === Gson jar path ===
set GSON_JAR=lib\gson-2.10.1.jar

:: === JavaFX rendering settings (software mode for compatibility) ===
set JFX_OPTS=-Dprism.order=sw -Dprism.verbose=true

echo [INFO] Checking and installing Python modules...
python -c "import paramiko" 2>nul || (
    echo [INFO] Installing missing module: paramiko...
    python -m pip install paramiko
)

echo [INFO] Compiling JavaFX GUI...
javac --module-path %FX_LIB% --add-modules javafx.controls -cp %GSON_JAR% DefaultPasswordDetector.java

if %errorlevel% neq 0 (
    echo [ERROR] Java compilation failed. Make sure JavaFX and gson jar are present.
    pause
    exit /b
)

echo [INFO] Launching GUI tool...
java %JFX_OPTS% --module-path %FX_LIB% --add-modules javafx.controls -cp ".;%GSON_JAR%" DefaultPasswordDetector

pause
