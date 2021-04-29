# Workstation setup
Run from an administrative PowerShell console:

`Invoke-Expression "(Invoke-WebRequest https://raw.githubusercontent.com/MrAlexFranco/dev-workstation/master/Initialize.ps1 -UseBasicParsing).Content" | Out-File $env:USERPROFILE\Initialize.ps1; & $env:USERPROFILE\Initialize.ps1 -FirstRun`