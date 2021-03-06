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
New-Item -Path Env:\ -Name DEV -Value "$env:USERPROFILE\OneDrive - Franco.dev\dev" -Force | Out-Null
Set-Alias -Name ~ -Value $env:USERPROFILE

Set-Location $env:DEV
