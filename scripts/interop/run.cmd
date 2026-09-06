@echo off

rem Кодовая страница UTF-8: иначе строки ниже читаются как мусор.

chcp 65001 >nul
rem Запуск проверки о чужие реализации одной командой на Windows.
rem
rem Нужен затем, что сама проверка написана на bash, а bash в Windows живёт
rem внутри Git for Windows и в `PATH` обычно не лежит. Искать его руками
rem каждый раз — лишняя работа для того, кто просто хочет прогнать проверку.
rem
rem   scripts\interop\run.cmd            все протоколы
rem   scripts\interop\run.cmd socks5     один
rem
rem Отчёт остаётся в `scripts\interop\report.txt` рядом с этим файлом.

setlocal
set "HERE=%~dp0"
set "BASH="

rem Git for Windows ставят куда угодно, в том числе не на системный диск, —
rem поэтому список известных мест идёт последним, а не первым.

rem 1. Сам bash в PATH: так бывает, если запускают из окна Git Bash.
for /f "delims=" %%P in ('where bash.exe 2^>nul') do if not defined BASH set "BASH=%%~P"

rem 2. Рядом с git: он лежит в `...\Git\cmd\git.exe`, а bash — в `...\Git\bin`.
if not defined BASH for /f "delims=" %%P in ('where git.exe 2^>nul') do (
  if not defined BASH if exist "%%~dpP..\bin\bash.exe" set "BASH=%%~dpP..\bin\bash.exe"
)

rem 3. Реестр: установщик пишет туда путь, каким бы он ни был.
if not defined BASH for %%K in (HKLM HKCU) do (
  for /f "tokens=2,*" %%A in ('reg query %%K\SOFTWARE\GitForWindows /v InstallPath 2^>nul ^| find "InstallPath"') do (
    if not defined BASH if exist "%%B\bin\bash.exe" set "BASH=%%B\bin\bash.exe"
  )
)

rem 4. Обычные места — на случай установки без записи в реестр.
if not defined BASH for %%P in (
  "%ProgramFiles%\Git\bin\bash.exe"
  "%ProgramFiles(x86)%\Git\bin\bash.exe"
  "%ProgramW6432%\Git\bin\bash.exe"
  "%LOCALAPPDATA%\Programs\Git\bin\bash.exe"
) do if not defined BASH if exist %%P set "BASH=%%~P"

if not defined BASH (
  echo.
  echo Не найден bash из Git for Windows.
  echo Проверка написана на bash; поставьте Git for Windows и повторите:
  echo   https://git-scm.com/download/win
  exit /b 1
)

rem Косые черты вместо обратных: bash понимает "C:/путь", а "C:\путь" — нет.
"%BASH%" -c "cd '%HERE:\=/%' && ./run.sh %*"
exit /b %ERRORLEVEL%
