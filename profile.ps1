# $PSDefaultParameterValues
$PSDefaultParameterValues.Add("Format-Table:AutoSize", $true)
$PSDefaultParameterValues.Add("Export-Excel:AutoSize", $true)
$PSDefaultParameterValues.Add("Export-Excel:FreezeTopRow", $true)
$PSDefaultParameterValues.Add("Export-Excel:BoldTopRow", $true)
$PSDefaultParameterValues.Add("Export-Excel:TableStyle", "None")

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

# Region Custom Prompt
oh-my-posh init pwsh --config "$env:USERPROFILE\.material.json" | Invoke-Expression
