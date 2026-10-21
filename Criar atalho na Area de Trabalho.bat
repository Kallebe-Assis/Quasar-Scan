@echo off
rem Cria o atalho "Quasar Scan" na Area de Trabalho deste computador.
rem Deixe este arquivo na mesma pasta do QuasarScan.exe.
set "EXE=%~dp0QuasarScan.exe"
if not exist "%EXE%" (
  echo QuasarScan.exe nao encontrado nesta pasta.
  pause
  exit /b 1
)
powershell -NoProfile -Command "$d=[Environment]::GetFolderPath('Desktop'); $s=(New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $d 'Quasar Scan.lnk')); $s.TargetPath=$env:EXE; $s.WorkingDirectory='%~dp0'; $s.IconLocation=$env:EXE+',0'; $s.Description='Diagnostico e descoberta da rede local'; $s.Save()"
echo Atalho "Quasar Scan" criado na Area de Trabalho.
pause
