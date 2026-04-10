if ($env:USERDNSDOMAIN -eq "WECI.NET") {
    $Credential = Get-Secret -Name "afranco-admin"
    $PSDefaultParameterValues.Add("Invoke-Command:Credential", $Credential)
    $PSDefaultParameterValues.Add("Enter-PSSession:Credential", $Credential)
}

# Set-PSReadLineOptions
Set-PSReadLineOption -HistoryNoDuplicates:$true -PredictionSource "History" -PredictionViewStyle "ListView"

# Set Vars
New-Item -Path "Env:\" -Name "CODE" -Value "$HOME\Code" -Force | Out-Null
Set-Location -Path $env:CODE

# Prompt
oh-my-posh init pwsh --config "$env:USERPROFILE\material.omp.json" | Invoke-Expression

# Remind myself what functions I've already written
$ExportedFunctions = Get-Module -Name "AlexFranco" -ListAvailable | Select-Object -ExpandProperty "ExportedFunctions" | Select-Object -ExpandProperty "Keys"
Write-Host "Exported functions from AlexFranco module:" -ForegroundColor Cyan
for ($n = 0; $n -lt $ExportedFunctions.Count; $n += 5) {
    Write-Host " $($ExportedFunctions[$n..($n + 4)] -join ", ")" -ForegroundColor Cyan
}
