[cmdletbinding()]
param(
    [Parameter(Mandatory=$True)]
    [String]
    $ComputerName,

    [Parameter(Mandatory=$False)]
    [String]
    $Subject = "CN=",

    [Parameter(Mandatory=$True)]
    [String]
    $ChallengePassword,

    [Parameter(Mandatory=$False)]
    [Switch]
    $UseSSL = $False,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({$_ | ForEach-Object -Process {
        [System.Uri]::CheckHostName($_) -eq [System.UriHostnameType]::Dns
    }})]
    [String[]]
    $DnsName,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [mailaddress[]]
    $Upn,

    [Parameter(Mandatory=$False)]
    [ValidateSet(1024,2048,3072,4096)]
    [Int]
    $KeyLength = 2048,

    [Parameter(Mandatory=$False)]
    [Switch]
    $MachineContext = $False
)

begin {
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Value 11

    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64HEADER -Value 0x0
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 0x1
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BINARY -Value 0x2

    New-Variable -Option Constant -Name SCEPProcessDefault -Value 0x0
    New-Variable -Option Constant -Name SCEPProcessSkipCertInstall -Value 0x1

    New-Variable -Option Constant -Name SCEPDispositionSuccess -Value 0
    New-Variable -Option Constant -Name SCEPDispositionFailure -Value 2
}

process {

    If ($MachineContext.IsPresent) {

        # Check if the Script is ran with Elevation
        If (-not (
            [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error -Message "This Script must be run with Elevation (Run as Administrator) when using the Machine Context!" 
            return
        }
    }

    If ($UseSSL)
        { $Protocol = "https" }
    Else 
        { $Protocol = "http" }

    $ConfigString = "$($Protocol)://$($ComputerName)/certsrv/mscep/mscep.dll/pkiclient.exe"

    $Pkcs10 = New-Object -ComObject "X509Enrollment.CX509CertificateRequestPkcs10"
    $Pkcs10.Initialize([int]($MachineContext.IsPresent)+1)

    try {
        # To Do: implement Validation of the Subject RDN
        $DnObject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
        $DnObject.Encode($Subject)
        $Pkcs10.Subject = $DnObject
    }
    catch {
        #
    }

    If ($ChallengePassword) {
        $Pkcs10.ChallengePassword = $ChallengePassword
    }

    $Pkcs10.PrivateKey.Length = $KeyLength

    # Set the Subject Alternative Names Extension if specified as Argument
    If ($Upn -or $DnsName) {

        $SansExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames

        Foreach ($Entry in $Upn) {
        
            $SanType = $XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME
            # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
            $SanEntry = New-Object -ComObject X509Enrollment.CAlternativeName
            $SanEntry.InitializeFromString($SanType, $Entry.Address)
            $Sans.Add($SanEntry)

        }

        Foreach ($Entry in $DnsName) {
        
            $SanType = $XCN_CERT_ALT_NAME_DNS_NAME
            # https://msdn.microsoft.com/en-us/library/aa374981(VS.85).aspx
            $SanEntry = New-Object -ComObject X509Enrollment.CAlternativeName
            $SanEntry.InitializeFromString($SanType, $Entry)
            $Sans.Add($SanEntry)

        }
        
        $SansExtension.InitializeEncode($Sans)

        # Adding the Extension to the Certificate
        $Pkcs10.X509Extensions.Add($SansExtension)

    }

    $Helper = New-Object -ComObject "X509Enrollment.CX509SCEPEnrollmentHelper"

    $Helper.Initialize(
        $ConfigString,
        [String]::Empty,
        $Pkcs10,
        [String]::Empty
        )

    # Enroll for the Certificate via NDES
    try {
        $Disposition = $Helper.Enroll($SCEPProcessDefault)
    }
    catch {
        Write-Error -Message $_.Exception.Message
        return
    }

    # Process the Result
    switch ($Disposition) {
        $SCEPDispositionFailure {
            # Throw the HTML Response of the SCEP Request which will contain the Error Code
            Write-Error $Helper.ResultMessageText

            # Das Zertifikat ist für den angeforderten Zweck nicht zugelassen. 0x800b0110 (-2146762480 CERT_E_WRONG_USAGE) - Wrong Password
        }
        $SCEPDispositionSuccess {
            # Show the Certificate, but it is also installed in the selected Certificate Store
            $CertificateBase64 = $Helper.X509SCEPEnrollment.Certificate($XCN_CRYPT_STRING_BASE64)

            # We load the Certificate into an X509Certificate2 Object
            $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $CertificateObject.Import([Convert]::FromBase64String($CertificateBase64))
            $CertificateObject
        }
        default {
            # Throw the Return Disposition Code. Not further implemented atm.
            Write-Host "X509SCEPDisposition: $Disposition"
        }
    }
}
