#Requires -RunAsAdministrator

[cmdletbinding()]
param (
    [switch]$FirstRun
)

$apps = @(
    '7zip.7zip'
    'Audacity.Audacity'
    'CodecGuide.K-LiteCodecPackStandard'
    'DominikReichl.KeePass'
    'Git.Git'
    'Google.Chrome'
    'Insecure.Nmap'
    'Microsoft.PowerShell'
    'Microsoft.PowerToys'
    'Microsoft.VisualStudioCode'
    'Microsoft.WindowsTerminal'
    'Mozilla.FireFox'
    'Notepad++.Notepad++'
    'PuTTY.PuTTY'
    'Python.Python'
    'ProtonTechnologies.ProtonVPN'
    'VideoLAN.VLC'
    'Win32diskimager.win32diskimager'
    'WiresharkFoundation.Wireshark'
)

if ($FirstRun) {
    # Winget
    $apps | ForEach-Object { winget install $_ }

    # Install the PowerLine fonts that make my prompt look nifty
    Set-Location $env:USERPROFILE
    git clone 'https://github.com/powerline/fonts.git'
    Push-Location fonts
    & .\install.ps1 -FontName DejaVu*
    Pop-Location

    # PowerShell modules
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    Install-PackageProvider -Name NuGet -Force
    Update-Module -Name PowerShellGet -RequiredVersion 2.2.5

    Install-Module -Name PSReadLine -AllowPrerelease -Force
    $moduleList = 'ImportExcel', 'KaceSMA', 'Posh-SSH', 'MSOnline'

    $moduleList | ForEach-Object {
        $moduleName = $_
        Write-Host $moduleName
    
        Install-Module $moduleName
    }

    # RSAT
    $allFeatures = Get-WindowsCapability -Online

    $featureList = 'Rsat.ServerManager.Tools', 'Rsat.DHCP.Tools', 'Rsat.Dns.Tools', 'Rsat.ActiveDirectory', 'Rsat.GroupPolicy.Management'
    $featureList | ForEach-Object {
        $name = $_

        $feature = $allFeatures | Where-Object { $_.Name -match $name }

        if ($feature.State -ne 'Installed') {
            Add-WindowsCapability -Name $feature.Name -Online
        }
    }

    # Show extensions for known file types; current user
    Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Value 0

    # Show extensions for known file types; all users
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt' -Name 'DefaultValue' -Value 0
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt' -Name 'CheckedValue' -Value 0

    # Regkey to turn off UAC consent prompt behavior for Admins; NOT disabling UAC gloablly
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 0

}
else {
    $apps | ForEach-Object { $_; winget upgrade --id $_; '' }
}

# Copy profile
'Updating PowerShell profiles...'
$profileContent = (Invoke-WebRequest 'https://raw.githubusercontent.com/MrAlexFranco/workstation/master/profile.ps1' -UseBasicParsing).Content
foreach ($proPath in @(
        "$($env:userprofile)\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
        "$($env:userprofile)\Documents\PowerShell\Microsoft.VSCode_profile.ps1"
        "$($env:userprofile)\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
        "$($env:userprofile)\Documents\WindowsPowerShell\Microsoft.VSCode_profile.ps1"
    )) {

    Remove-Item -Path $proPath -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $proPath -Force | Out-Null
    Set-Content -Value $profileContent -Path $proPath | Out-Null
}

# AlexFranco module
'Updating AlexFranco.psm1...'
$moduleContent = (Invoke-WebRequest 'https://raw.githubusercontent.com/MrAlexFranco/workstation/master/AlexFranco.psm1' -UseBasicParsing).Content
$modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\AlexFranco\AlexFranco.psm1"
Remove-Item -Path $modulePath -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $modulePath -Force | Out-Null
Set-Content -Path $modulePath -Value $moduleContent | Out-Null

# Microsoft Terminal settings
'Updating Microsoft Terminal settings...'
$terminalSettings = (Invoke-WebRequest 'https://raw.githubusercontent.com/MrAlexFranco/workstation/master/settings.json' -UseBasicParsing).Content
$settingsPath = Resolve-Path "$env:USERPROFILE\AppData\Local\Packages\Microsoft.WindowsTerminal_*\LocalState\settings.json"
Remove-Item -Path $settingsPath -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $settingsPath -Force | Out-Null
Set-Content -Path $settingsPath -Value $terminalSettings | Out-Null
