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
        $Quiet = $false,
        [Int]
        $Delay = 1
    )

    while ($true) {
        $ping = Test-Connection $ComputerName -Count 1 -Quiet
        if ($ping) {
            Write-Host -NoNewline '!'
            if (!$Quiet) { [Console]::Beep() }
        } else {
            Write-Host -NoNewline '.'
        }
        Start-Sleep -Seconds $Delay
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

function Send-Email {
    [CmdletBinding()]
    param (
        [string[]]$To,
        [string[]]$CC,
        [string[]]$BCC,
        [string]$From,
        [string]$Subject,
        [string]$Body,
        [string[]]$Attachments,
        [bool]$BodyAsHtml,
        [string]$SmtpServer,
        [int]$Port
    )

    # Construct message
    $Message = New-Object System.Net.Mail.MailMessage

    $To | ForEach-Object -Process {
        $Message.To.Add($_)
    }

    if ($CC) {
        $CC | ForEach-Object -Process {
            $Message.CC.Add($_)
        }
    }

    if ($BCC) {
        $BCC | ForEach-Object -Process {
            $Message.BCC.Add($_)
        }
    }

    $Message.From = $From
    $Message.Subject = $Subject
    $Message.Body = $Body
    $Message.IsBodyHtml = if ($BodyAsHtml) { $BodyAsHtml } else { $false }

    if ($Attachments) {
        $Attachments | ForEach-Object -Process {
            $Attachment = New-Object System.Net.Mail.Attachment($_)
            $Message.Attachments.Add($Attachment)
        }
    }

    # Construct SMTP client
    $Client = New-Object System.Net.Mail.SmtpClient
    $Client.Host = if ($SmtpServer) { $SmtpServer } else { "relay.weci.net" }
    $Client.Port = if ($Port) { $Port } else { 25 }
    $Client.EnableSsl = $false

    try {
        $Client.Send($Message)
        $Client.Dispose()
        $Message.Dispose()
    }
    catch {
        Write-Error -Message $_.Exception.Message
    }
}

function Test-SSLCertificate {
    [CmdletBinding()]
    param(
        [String]$Server,
        [int]$Port
    )

    if (!(Test-Path -Path "C:\Program Files\Git\usr\bin\openssl.exe")) {
        throw "OpenSSL not found at 'C:\Program Files\Git\usr\bin\openssl.exe'"
    }

    $OpenSSL = @{
        FilePath     = "C:\Program Files\Git\usr\bin\openssl.exe"
        ArgumentList = @(
            "s_client"
            "-no-interactive"
            "-connect $Server`:$Port"
        )
        Wait         = $true
        NoNewWindow  = $true
    }
    
    Start-Process @OpenSSL
}

function Add-DigitalSignature {
    [CmdletBinding()]
    param(
        [String]$FilePath,
        [string]$SignToolPath = "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"
    )

    # Check for SignTool
    if (!(Test-Path -Path $SignToolPath)) {
        Write-Host "SignTool.exe not found at $SignToolPath." -ForegroundColor Yellow
        Write-Host "- Searching for SignTool.exe. . . " -NoNewline

        @(
            "C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"            
            "C:\Program Files (x86)\Windows Kits\10\Tools\bin\i386\signtool.exe"
        ) | ForEach-Object -Process {
            if (Test-Path -Path $_) {
                $SignToolPath = $_
                Write-Host "OK" -ForegroundColor Green
                Write-Host "- SignTool.exe found at $SignToolPath."
                break
            }
        }
    }

    # Digital signature
    ## Get the code signing certificate
    $CertStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "My", "CurrentUser"
    $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $CertCollection = $CertStore.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByExtension, "Enhanced Key Usage", $true)
    $CertStore.Close()

    $Cert = $CertCollection | Where-Object { $_.EnhancedKeyUsageList.FriendlyName -eq "Code Signing" }
    if (-not (Test-Certificate -Cert $Cert)) {
        throw @"
Code Signing certificate in CurrentUser X509 store not found or not valid.
    `$CertStore = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList "My", "CurrentUser"
    `$CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    `$CertCollection = `$CertStore.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByExtension, "Enhanced Key Usage", `$true)
    `$CertStore.Close()

    `$Cert = `$CertCollection | Where-Object { `$_.EnhancedKeyUsageList.FriendlyName -eq "Code Signing" }

    (Test-Certificate -Cert `$Cert) = `$false
"@
        break
    }

    # Sign the executable
    $SignToolParams = @{
        FilePath     = $SignToolPath
        ArgumentList = @(
            "sign"
            "/a"
            "/s MY"
            "/sha1 $($Cert.Thumbprint)"
            "/fd certHash"        
            "/t http://timestamp.digicert.com"
            "/v"
            "`"$FilePath`""
        )
        Wait         = $true
        NoNewWindow  = $true
    }

    Start-Process @SignToolParams
}

function Compare-Xml {
    param(
        [System.Xml.XmlNode]$DifferenceObject,
        [System.Xml.XmlNode]$ReferenceObject,
        [Switch]$Quiet = $false
    )

    $DifferenceCount = 0

    if ($DifferenceObject.Name -ne $ReferenceObject.Name) {
        Write-Host "- Name mismatch"
        Write-Host "  - Reference: $($ReferenceObject.Name)"
        Write-Host "  - Difference: $($DifferenceObject.Name)"
        $DifferenceCount++
        Write-Host "`r`n"
    }

    # Attributes
    if ($DifferenceObject.Attributes.Count -ne $ReferenceObject.Attributes.Count) {
        Write-Host "- Attribute count mismatch"
        Write-Host "  - Reference: $($ReferenceObject.Attributes.Count)"
        Write-Host "  - Difference: $($DifferenceObject.Attributes.Count)"
        $DifferenceCount++
        Write-Host "`r`n"
    }

    for ($i = 0; $i -lt $ReferenceObject.Attributes.Count; $i++) {
        if ($ReferenceObject.Attributes[$i].Name -ne $DifferenceObject.Attributes[$i].Name) {
            Write-Host "- Attribute name mismatch"
            Write-Host "  - Reference: $($ReferenceObject.Attributes[$i].Name)"
            Write-Host "  - Difference: $($ReferenceObject.Attributes[$i].Name)"
            $DifferenceCount++
            Write-Host "`r`n"
        }
        if ($ReferenceObject.Attributes[$i].Value -ne $DifferenceObject.Attributes[$i].Value) {
            Write-Host "- Attribute value mismatch"
            Write-Host "  - Reference: $($ReferenceObject.Attributes[$i].Value)"
            Write-Host "  - Difference: $($ReferenceObject.Attributes[$i].Value)"
            $DifferenceCount++
            Write-Host "`r`n"
        }
    }
    
    # Children
    if ($ReferenceObject.ChildNodes.Count -ne $DifferenceObject.ChildNodes.Count) {
        Write-Host "- Child Node count mismatch"
        Write-Host "  - Reference: $($ReferenceObject.ChildNodes.Count)"
        Write-Host "  - Difference: $($DifferenceObject.ChildNodes.Count)"
        $DifferenceCount++
        Write-Host "`r`n"
    }
        
    for ($i = 0; $i -lt $ReferenceObject.ChildNodes.Count; $i++) {
        if (-not $DifferenceObject.ChildNodes[$i]) {
            Write-Host "- Missing child node"
            Write-Host "  - Reference: $($ReferenceObject.ChildNodes[$i].Name)"
            Write-Host "  - Difference: Missing"
            $DifferenceCount++
            Write-Host "`r`n"
        }

        Compare-Xml -DifferenceObject $DifferenceObject.ChildNodes[$i] -ReferenceObject $ReferenceObject.ChildNodes[$i] -Quiet:$true
    }
    
    if ($ReferenceObject.InnerText) {
        if ($ReferenceObject.InnerText -ne $DifferenceObject.InnerText) {
            Write-Host "- Inner Text mismatch"
            Write-Host "  - Reference: $($ReferenceObject.InnerText)"
            Write-Host "  - Difference: $($DifferenceObject.InnerText)"
            $DifferenceCount++
            Write-Host "`r`n"
        }
    }
    elseif ($DifferenceObject.InnerText) {
        Write-Host "Difference has inner text but expected does not for Differenc = " + $DifferenceObject.Name
    }

    if (-not $Quiet) {
        if ($DifferenceCount -eq 0) {
            Write-Host "No differences found"
        }
        else {
            Write-Host "Found $DifferenceCount differences"
        }
    }
}

function New-CertificateSigningRequest {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [string]$Subject,        
        [Parameter(Mandatory = $True)]
        [string[]]$SubjectAlternateName,
        [Parameter(Mandatory = $True)]
        [string]$Template,        
        [Parameter(Mandatory = $True)]
        [string]$Exportable,        
        [bool]$ExportCertificate,
        [string]$ExportPath,        
        [securestring]$PfxPassword
    )
   
    $ErrorActionPreference = 'Inquire'

    ## Gathering Logic for SAN
    $SAN = "{text}dns=$($SubjectAlternateName[0])"

    if ($SubjectAlternateName.Count -gt 1) {
        $SubjectAlternateName[1..$SubjectAlternateName.Count] | ForEach-Object -Process {
            $SAN += "&dns=$_"
        }
    }

    ## Required Because Powershell interprets $Windows as a variable not a string
    $Windows = '$Windows'
    # KeyUsage = 0xf0

    $inputfiletemplate = @"
[Version]
Signature="$Windows NT$"

[NewRequest]
Subject = "CN=$Subject"
Exportable = $Exportable
KeyLength = 2048
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = True
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
SMIME = FALSE
RequestType = CMC

[Strings] 
szOID_SUBJECT_ALT_NAME2 = "2.5.29.17" 
szOID_ENHANCED_KEY_USAGE = "2.5.29.37" 
szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1" 
szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

[Extensions] 
%szOID_SUBJECT_ALT_NAME2% = "$SAN" 
%szOID_ENHANCED_KEY_USAGE% = "{text}%szOID_PKIX_KP_SERVER_AUTH%,%szOID_PKIX_KP_CLIENT_AUTH%"

[RequestAttributes] 
CertificateTemplate=$Template
"@

    ### Gathering Certificate information ###
    $filename = $Subject.Substring(0, 3)

    ### Make allowance for wildcard CNs
    if ($filename -like "*") {
        Write-Host "Hang on...have to create a new filename..."
        $filename = ( -join ((65..90) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ }))
    }

    $inputfiletemplate | Out-File "$filename.inf"

    Write-Host "Generating request"

    ### End of Gathering Certificate information ###

    # Using Certreq to request a new certificate with information file and request
    & "C:\Windows\System32\certreq.exe" "-new" "$filename.inf" "$filename.req"

    # Submitting Request to CA with request and saving file as a .cer
    $CertSubmitDateTime = Get-Date
    Write-Host "Submitting request to CA"
    & "C:\Windows\System32\certreq.exe" "-submit" "-config" "SCSRV82.weci.net\SubCa" "$filename.req" "$filename.cer"

    # Accepting the certificate from SubCA
    & "C:\Windows\System32\certreq.exe" "-accept" "$filename.cer"
    Write-Host "Certificate Imported Successfully"

    # File cleanup
    Write-Host "Cleaning up files generated"
    Remove-Item "$filename.*" -Force

    # Asking if you would like to export the certificate 
    if ($Exportable -eq $true -and $ExportCertificate -eq $true) {
        if (-not $ExportPath) {
            $ExportPath = ".\$Subject.pfx"
        }
        else {
            $ExportDirectory = Split-Path -Path $ExportPath -Parent

            if (-not (Test-Path -Path $ExportDirectory)) {
                New-Item -Path $ExportDirectory -ItemType Directory | Out-Null
            }
        }
        
        #Show certifiate store 
        Write-Host "Fetching Certificates in store for you..."
        $CertStore = Get-ChildItem -Path "Cert:\LocalMachine\my" | Where-Object -FilterScript { $_.Subject -match $Subject -and $_.NotBefore -gt $CertSubmitDateTime.AddMinutes(-180) }

        if ($CertStore.Count -eq 1) {
            $CertChoice = $CertStore[0]
        }
        else {
            $CertChoice = $CertStore | Select-Object -Property "Subject", "EnhancedKeyUsageList", "NotBefore", "NotAfter", "Thumbprint" | Out-GridView -PassThru
        }

        # Export certificate with password
        $ExportParams = @{
            Password    = if ($PfxPassword) { $PfxPassword } else { Read-Host -Prompt "Please type your password" -AsSecureString }
            ChainOption = "BuildChain"
            NoClobber   = $true
            FilePath    = if ($ExportPath) { $ExportPath } else { Read-Host -Prompt "Give the PFX a filename with .pfx" }
        }

        if (-not (Split-Path -Path $ExportPath -Parent | Test-Path)) { New-Item -ItemType Directory -Force }
        Get-ChildItem -Path "Cert:\LocalMachine\my\$($CertChoice.Thumbprint)" | Export-PfxCertificate @ExportParams
    }
}
