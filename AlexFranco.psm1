function Get-ProductSupport {
    [CmdletBinding()]
    param (
        [Parameter()]
        [ValidateSet(
            'Dell',
            'Lenovo'
        )]
        [String]
        $Manufacturer,

        [Parameter()]
        [string]
        $SerialNumber,

        [Parameter()]
        [Switch]
        $Show
    )

    if (!($Manufacturer) -and !($SerialNumber)) {
        $BIOS = Get-CimInstance -ClassName Win32_BIOS
        [String]$Manufacturer = $BIOS.Manufacturer.ToString()
        [String]$SerialNumber = $BIOS.SerialNumber.ToString()
    }

    switch -Regex ($Manufacturer) {
        'Dell' { $URL = 'https://www.dell.com/support/home/en-us/product-support/servicetag/{0}' -f $SerialNumber }
        'Lenovo' { $URL = 'https://pcsupport.lenovo.com/us/en/products/{0}' -f $SerialNumber }
        Default { $URL = $null }
    }

    if ($URL -and $Show) {
        Start-Process $URL
    }

    $obj = [pscustomobject]@{
        Manufacturer = $Manufacturer
        SerialNumber = $SerialNumber
        URL          = $URL
    }

    return $obj
}

function Test-Network {
    param(
        [Parameter()]
        [IPAddress[]]
        $IPAddress
    )

    if (!($IPAddress)) {
        $IPAddress = @()

        $NetIPConfig = Get-NetIPConfiguration | Where-Object -FilterScript {
            $null -ne $_.IPv4Address -and
            $null -ne $_.IPv4DefaultGateway -and
            $null -ne $_.DNSServer
        }

        $self = $NetIPConfig.IPv4Address.IPAddress
        $defaultGateway = $NetIPConfig.IPv4DefaultGateway.NextHop
        $dns = $NetIPConfig.DNSServer.ServerAddresses

        $IPAddress += $self
        $IPAddress += $defaultGateway
        $IPAddress += $dns
        $IPAddress += '1.1.1.1'
        $IPAddress += '8.8.8.8'
    }

    $DefaultFGColor = $Host.UI.RawUI.ForegroundColor

    $IPAddress | ForEach-Object {
        $ping = Test-Connection -ComputerName $_ -Count 1 | Select-Object -Property Destination, Status
        $ping
    }
}

function ping2 {
    param (
        [Parameter(Mandatory)]
        $ComputerName,
        [Switch]
        $Quiet = $false
    )

    while ($true) {
        $ping = Test-Connection $ComputerName -Count 1 -Quiet
        if ($ping) {
            Write-Host -NoNewline '!'
            if (!$Quiet) { [Console]::Beep() }
        } else {
            Write-Host -NoNewline '.'
        }
        Start-Sleep -Seconds 1
    }
}

function Get-MACVendor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript(
            {
                if ($_ -match '[a-zA-Z0-9][a-zA-Z0-9]\-[a-zA-Z0-9][a-zA-Z0-9]\-[a-zA-Z0-9][a-zA-Z0-9]' -or `
                        $_ -match '[a-zA-Z0-9][a-zA-Z0-9]\:[a-zA-Z0-9][a-zA-Z0-9]\:[a-zA-Z0-9][a-zA-Z0-9]' -or `
                        $_ -match '[a-zA-Z0-9][a-zA-Z0-9]\.[a-zA-Z0-9][a-zA-Z0-9]\.[a-zA-Z0-9][a-zA-Z0-9]' -or `
                        $_ -match '[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]' -or `
                        $_ -match '[a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9][a-zA-Z0-9]\.[a-zA-Z0-9][a-zA-Z0-9]') {
                    $true
                } else {
                    throw 'Invalid or incomplete MAC address format.'
                    $false
                }
            }
        )]
        [String]
        $MACAddress
    )
    
    $url = "https://api.macvendors.com/"
    $request = Invoke-RestMethod -Uri ($url + $MACAddress) -Method Get

    return $request
}
