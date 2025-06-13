if ($env:USERDNSDOMAIN -eq "WECI.NET") {
    $Credential = Get-Secret -Name "afranco-admin"
    $PSDefaultParameterValues.Add("Invoke-Command:Credential", $Credential)
    $PSDefaultParameterValues.Add("Enter-PSSession:Credential", $Credential)
}

# Set-PSReadLineOptions
Set-PSReadLineOption -HistoryNoDuplicates:$true -PredictionSource "History" -PredictionViewStyle "ListView"

# Set Vars
New-Item -Path "Env:\" -Name "CODE" -Value "$env:USERPROFILE\OneDrive - Franco.dev\Code" -Force | Out-Null
Set-Location -Path $env:CODE

# Prompt
oh-my-posh init pwsh --config "$env:USERPROFILE\material.omp.json" | Invoke-Expression
