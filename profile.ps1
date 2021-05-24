Clear-Host

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

#Region Custom Prompt
<#
Custom Prompt
Inspired by Basic To Boss: Customizing Your PowerShell Prompt by Thomas Rayner at PowerShell Summit 2019
https://www.youtube.com/watch?v=SdQYooRg7Cw

Requires:
    Powerline module: https://www.powershellgallery.com/packages/PowerLine
    Fonts: https://github.com/thomasrayner/fonts
#>

<#
$global:forePromptColor = 0
$global:leftArrow = [char]0xe0b2
$global:rightArrow = [char]0xe0b0
$global:esc = "$([char]27)"
$global:fore = "$esc[38;5"
$global:back = "$esc[48;5"
$global:prompt = ''
$global:cursor = [char]0xE0B1


[System.Collections.Generic.List[ScriptBlock]]$global:PromptRight = @(
    # right aligned
    { "$fore;${errorColor}m$back;${forePromptColor}m{0}" -f $leftArrow }
    { "$fore;${forePromptColor}m$back;${errorColor}m{0}" -f $(if (@(get-history).Count -gt 0) { (get-history)[-1] | ForEach-Object { "{0:c}" -f (New-TimeSpan $_.StartExecutionTime $_.EndExecutionTime) } } else { '00:00:00.0000000' }) }

    { "$fore;7m$back;${errorColor}m{0}" -f $leftArrow }
    { "$fore;0m$back;7m{0}" -f $(Get-Date -format "hh:mm:ss tt") }
)

[System.Collections.Generic.List[ScriptBlock]]$global:PromptLeft = @(
    # left aligned
    { "$back;${errorColor}m$fore;${forePromptColor}m{0}$esc[0m" -f ( ($PWD -split '\\')[-3..-1] -join '\' ) }
    { "$back;${forePromptColor}m$fore;${errorColor}m{0}" -f $rightArrow }
)

function global:prompt {
    $global:errorColor = if ($?) { 22 } else { 1 }
    $global:platformColor = if ($isWindows) { 11 } else { 117 }

    $leftSide = -join @($global:PromptLeft).Invoke()
    $rightSide = -join ($global:promptRight).Invoke()

    $offset = $global:host.UI.RawUI.BufferSize.Width - 28
    $prompt = -join @($leftSide, "$esc[${offset}G", $rightSide, "$esc[0m" + "`n`r" + $cursor + ' ')
    $prompt
}
#EndRegion Custom Prompt
#>
