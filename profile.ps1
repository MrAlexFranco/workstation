Clear-Host

# $PSDefaultParameterValues
$PSDefaultParameterValues.Add("Format-Table:AutoSize", $true)

if ($env:USERDNSDOMAIN -eq "WECI.NET") {
    $PSDefaultParameterValues.Add("Invoke-Command:Credential", (Get-Secret -Name "afranco-admin"))
    $PSDefaultParameterValues.Add("Enter-PSSession:Credential", (Get-Secret -Name "afranco-admin"))
}

# Set-PSReadLineOptions
$PSreadLineOption = @{
    HistoryNoDuplicates = $true
    PredictionSource    = "History"
    PredictionViewStyle = "ListView"
}

Set-PSReadLineOption @PSReadLineOption

# Set Vars
New-Item -Path Env:\ -Name "CODE" -Value "$env:USERPROFILE\OneDrive - Franco.dev\Code" -Force | Out-Null
Set-Alias -Name ~ -Value $env:USERPROFILE

# Region Custom Prompt
if (Test-Path -Path "$env:USERPROFILE\.material.json") {
    oh-my-posh init pwsh --config "$env:USERPROFILE\.material.json" | Invoke-Expression
}

Set-Location $env:CODE
