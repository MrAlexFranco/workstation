Clear-Host

# Region Custom Prompt
oh-my-posh init pwsh --config $env:USERPROFILE\.material.json | Invoke-Expression

# Remove curl alias so it won't interfere with installed curl
Remove-Item -Path Alias:\curl -Force -ErrorAction SilentlyContinue

# Set-PSReadLineOptions
$PSreadLineOption = @{
    HistoryNoDuplicates = $true
    PredictionSource    = 'History'
    PredictionViewStyle = 'ListView'
}

Set-PSReadLineOption @PSReadLineOption

# Set Vars
New-Item -Path Env:\ -Name 'CODE' -Value "$env:USERPROFILE\OneDrive - Franco.dev\Code" -Force | Out-Null
Set-Alias -Name ~ -Value $env:USERPROFILE

Set-Location $env:CODE

# $PSDefaultParameterValues
$PSDefaultParameterValues.Add('Format-Table:AutoSize', $true)

if ($env:USERDNSDOMAIN -and $env:USERDNSDOMAIN -eq 'WECI.NET') {
    $PSDefaultParameterValues.Add('*:Credential', (Get-Secret -Name 'afranco-admin(PSCredential)'))    
}
