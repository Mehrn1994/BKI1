@echo off
echo ===============================================
echo Network Portal Installer
echo ===============================================
echo.

set INSTALL_DIR=C:\router-config-tool

echo Installation Directory: %INSTALL_DIR%
echo.

if not exist "%INSTALL_DIR%" (
    echo Creating directory...
    mkdir "%INSTALL_DIR%"
)

echo Creating backups...
if exist "%INSTALL_DIR%\data\network_ipam.db" (
    copy "%INSTALL_DIR%\data\network_ipam.db" "%INSTALL_DIR%\data\network_ipam_backup.db"
    echo Database backed up
)

echo.
echo Copying new files...

if not exist "%INSTALL_DIR%\data" mkdir "%INSTALL_DIR%\data"
if not exist "%INSTALL_DIR%\templates" mkdir "%INSTALL_DIR%\templates"
if not exist "%INSTALL_DIR%\excel_files" mkdir "%INSTALL_DIR%\excel_files"

copy /Y server_database.py "%INSTALL_DIR%\"
copy /Y rebuild_database.py "%INSTALL_DIR%\"
copy /Y data\network_ipam.db "%INSTALL_DIR%\data\"

copy /Y templates\*.html "%INSTALL_DIR%\templates\"
copy /Y excel_files\*.xlsx "%INSTALL_DIR%\excel_files\"

echo.
echo ===============================================
echo Installation Complete!
echo ===============================================
echo.
echo To start the server:
echo    cd %INSTALL_DIR%
echo    python server_database.py
echo.
pause
