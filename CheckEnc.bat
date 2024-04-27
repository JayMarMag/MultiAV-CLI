@echo off
setlocal enabledelayedexpansion

rem Set the directory path where the files are located
set "dir=Logs\"

rem Iterate through all .txt files in the directory
for /f "delims=" %%i in ('dir /b /a-d "%dir%\*.log"') do (
   rem Use the "chcp" command to set the ANSI code page
   chcp 65001 > nul
   rem Use the "type" command to read the file and redirect the output to a new file with the same name but with ANSI encoding
   type "%dir%\%%i" > "%dir%\%%i.ansi"
   rem Delete the original file
   del "%dir%\%%i"
   rem Rename the new file to the original file name
   ren "%dir%\%%i.ansi" "%%i"
)

echo Done!
