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
    'GIMP.GIMP'
    'Git.Git'
    'Google.Chrome'
    'Insecure.Nmap'
    'Microsoft.PowerShell'
    'Microsoft.PowerToys'
    'Microsoft.VisualStudioCode'
    'Microsoft.WindowsTerminal'
    'Mozilla.FireFox'
    'Notepad++.Notepad++'
    'OpenShot.OpenShot'
    'PuTTY.PuTTY'
    'Python.Python.3'
    'ProtonTechnologies.ProtonVPN'
    'SysInternals'
    'VideoLAN.VLC'
    'Win32diskimager.win32diskimager'
    'WiresharkFoundation.Wireshark'
)

if ($FirstRun) {
    # Winget
    $apps | ForEach-Object { winget install --id $_ }
    
    # Oh-my-posh
    winget install JanDeDobbeleer.OhMyPosh -s winget
    
    # PowerShell modules
    $command = {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
        Install-PackageProvider -Name 'NuGet' -Force

        Update-Module -Name 'PowerShellGet' -Force
        Update-Module -Name 'PSReadLine' -Force
        Install-Module -Name 'Oh-My-Posh' -Scope 'CurrentUser' -Force

        $moduleList = 'ImportExcel', 'KaceSMA', 'MSOnline', 'Microsoft.PowerShell.SecretManagement', 'Microsoft.PowerShell.SecretStore', 'Az.KeyVault'

        $moduleList | ForEach-Object {
            $moduleName = $_
            Write-Host $moduleName

            Install-Module $moduleName -Force
        }
    }
    
    Start-Process powershell.exe -ArgumentList '-ExecutionPolicy Bypass', '-NoProfile', "-Command $command"
    Start-Process pwsh.exe -ArgumentList '-ExecutionPolicy Bypass', '-NoProfile', "-Command $command"
    
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

    # 
    New-Item -Path C:\Temp -ItemType Directory
    New-Item -Path C:\Git\git.code-workspace -ItemType File -Force
    $gitWorkspace = @"
    {
        "folders": [
          {
            "path": "C:\\Git"
          }
        ],
    }
"@
    Set-Content -Path C:\Git\git.code-workspace -Value $gitWorkspace -Force
} else {
    $apps | ForEach-Object { $_; winget upgrade --id $_; '' }
}

'Removing junk...'
$remove = @(
	'Microsoft.BingNews'
	'Microsoft.BingWeather'
	'Microsoft.GamingApp'
	'Microsoft.GetHelp'
	'Microsoft.Getstarted'
	'Microsoft.MicrosoftSolitaireCollection'
	'Microsoft.MicrosoftStickyNotes'
	'Microsoft.People'
	'Microsoft.Windows.PeopleExperienceHost'
	'Microsoft.WindowsAlarms'
	'Microsoft.WindowsFeedbackHub'
	'Microsoft.WindowsMaps'
	'Xbox'
	'Microsoft.ZuneMusic'
	'Microsoft.ZuneVideo'
)

$remove | ForEach-Object -Process {
	$rmApp = $_
	"Removing $rmApp..."
	Get-AppxPackage -AllUsers | Where-Object { $_.Name -match $rmApp } | Remove-AppxPackage -AllUsers -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}

# Copy profile
'Updating PowerShell profiles...'
$profileContent = (Invoke-WebRequest 'https://raw.githubusercontent.com/MrAlexFranco/workstation/master/profile.ps1' -UseBasicParsing).Content
$profilePath = @(
    "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
    "$env:USERPROFILE\Documents\PowerShell\Microsoft.VSCode_profile.ps1"
    "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.VSCode_profile.ps1"
)
New-Item -Path $profilePath -Force | Out-Null
Set-Content -Value $profileContent -Path $profilePath | Out-Null

# AlexFranco module
'Updating AlexFranco.psm1...'
$moduleContent = (Invoke-WebRequest 'https://raw.githubusercontent.com/MrAlexFranco/workstation/master/AlexFranco.psm1' -UseBasicParsing).Content
$modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\AlexFranco\AlexFranco.psm1", "$env:USERPROFILE\Documents\PowerShell\Modules\AlexFranco\AlexFranco.psm1"
New-Item -Path $modulePath -Force | Out-Null
Set-Content -Path $modulePath -Value $moduleContent | Out-Null

# Microsoft Terminal settings
'Updating Microsoft Terminal settings...'
$terminalSettings = (Invoke-WebRequest 'https://raw.githubusercontent.com/MrAlexFranco/workstation/master/terminalsettings.json' -UseBasicParsing).Content
$settingsPath = (Resolve-Path "$env:USERPROFILE\AppData\Local\Packages\Microsoft.WindowsTerminal_*\LocalState\").Path + "\settings.json"
New-Item -Path $settingsPath -Force | Out-Null
Set-Content -Path $settingsPath -Value $terminalSettings | Out-Null

# Oh-my-posh
'Updating Oh-My-Posh settings...'
$themeSettings = (Invoke-WebRequest 'https://raw.githubusercontent.com/MrAlexFranco/workstation/master/.material.json' -UseBasicParsing).Content
$themePath = "$env:USERPROFILE\.material.json"
New-Item -Path $themePath -Force | Out-Null
Set-Content -Path $themePath -Value $themeSettings | Out-Null
