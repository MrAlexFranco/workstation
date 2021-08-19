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
        $ComputerName
    )

    while ($true) {
        $ping = Test-Connection $ComputerName -Count 1 -Quiet
        if ($ping) {
            Write-Host -NoNewline '!'
            [Console]::Beep()
        } else {
            Write-Host -NoNewline '.'
        }    
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

<#
.SYNOPSIS
    Simple script to connect to a server using Telnet, issue commands and
    capture all of the output.
.DESCRIPTION
    I wrote this script to connect to my Extreme Network switches and download
    their configuration.  I've also gotten it to work on Dell switches, though
    I had to adjust the WaitTime up a little bit to get all of the output.
    
    Because it is expected that you will be wanting to attach to several different
    devices to get their configurations I wrote this as a Function.  The intention
    is that at the bottom of the script you will have a list of devices you want
    to capture, and they may have different command and WaitTime requirements (as
    well as different output files).  I put several examples the script below, 
    with full explanations in the Help Section.
.PARAMETER Commands
    An array with a single command in each element.  Can be input from a file--
    using Get-Content--can come from the pipeline or be specified directly from
    the parameter.
    
    Note about Commands: If you have a dollar sign in your password you MUST
    escape it in order for it to work:
        Example:  -Commands "admin","$ecurePa$$word"
                  This will not work!
        Example:  -Commands "admin","`$ecurePa`$`$word"
                  This WILL work
.PARAMETER RemoteHost
    Name or IP address of the host you wish to connect to.
.PARAMETER Port
    Port number you need to attach to.
.PARAMETER WaitTime
    The amount of time the script waits in between issuing commands, in Milliseconds.
    When you run this script you must take a look at the output file to make sure
    you got all of the output you want.  If things are cut off then the script is
    running too quickly and you have to slow it down by using a higher number.
    1000 milliseconds is 1 second.
.PARAMETER OutputPath
    Full path and file name of where you want the script to save the output.
.INPUTS
    String input from Pipeline.
.OUTPUTS
    Text file at specified location.
.EXAMPLE
    Get-Telnet -RemoteHost "192.168.1.2" -OutputPath "\\server\share\hqswitches.txt"
    
    Will Telnet to 192.168.1.2 and execute the default commands, saving the output on
    the server as hqswitches.txt
.EXAMPLE
    Get-Telnet -RemoteHost "10.10.10.2" -Commands "admin","password","terminal datadump","show run" -OutputPath "\\server\share\DellHQswitches.txt" -WaitTime 2000
    
    Will Telnet to a Dell switch at 10.10.10.2, login using admin/password.  Issues the
    command terminal datadump (which tells Dell to not pause output) and than so the 
    full running configuration and save the output to the server as DellHQSwitches.txt.
    The WaitTime had to be adjusted to up because the script was running too fast for the
    switch.
.EXAMPLE
    Get-Telnet -RemoteHost "192.168.10.1" -Commands "admin","password","terminal pager 0","show run" -OutputPath "\\server\share\CiscoFirewall.txt"
    
    An example of how to connect to a Cisco ASA firewall and save the running config to 
    a file.
.EXAMPLE
    Get-Content "c:\scripts\commands.txt" | Get-Telnet -RemoteHost "192.168.10.1" -OutputPath "\\server\share\ciscoswitch.txt" -WaitTime 1500
    Get-Telnet -Commands (Get-Content "c:\scripts\commands.txt") -RemoteHost "192.168.10.1" -OutputPath "\\server\share\ciscoswitch.txt" -WaitTime 1500
    
    Two examples of how to use Get-Content to pull a series of commands from a text file
    and execute them.
.NOTES
    Author:            Martin Pugh
    Twitter:           @thesurlyadm1n
    Spiceworks:        Martin9700
    Blog:              www.thesurlyadmin.com
       
    Changelog:
       1.0             Initial Release
.LINK
    http://community.spiceworks.com/scripts/show/1887-get-telnet-telnet-to-a-device-and-issue-commands
#>

Function Get-Telnet {
    Param (
        [Parameter(Mandatory, ValueFromPipeline = $true)]
        [String[]]$Commands,

        [Parameter(Mandatory)]
        [string]$RemoteHost,

        [string]$Port = "23",
        [int]$WaitTime = 1000,
        [string]$OutputPath
    )

    # Attach to the remote device, setup streaming requirements
    $Socket = New-Object System.Net.Sockets.TcpClient($RemoteHost, $Port)

    If ($Socket) {
        $Stream = $Socket.GetStream()
        $Writer = New-Object System.IO.StreamWriter($Stream)
        $Buffer = New-Object System.Byte[] 1024 
        $Encoding = New-Object System.Text.AsciiEncoding

        # Now start issuing the commands
        ForEach ($Command in $Commands) {
            $Writer.WriteLine($Command) 
            $Writer.Flush()
            Start-Sleep -Milliseconds $WaitTime
        }

        # All commands issued, but since the last command is usually going to be
        # the longest let's wait a little longer for it to finish
        Start-Sleep -Milliseconds ($WaitTime * 4)
        $Result = ""
        # Save all the results
        While ($Stream.DataAvailable) {
            $Read = $Stream.Read($Buffer, 0, 1024) 
            $Result += ($Encoding.GetString($Buffer, 0, $Read))
        }
    } Else {
        $Result = "Unable to connect to host: $($RemoteHost):$Port"
    }
    
    if ($OutputPath) {
        $Result | Out-File $OutputPath
    }

    return $Result
}