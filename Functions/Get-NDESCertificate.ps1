<#
    .SYNOPSIS
    Requests a Certificate from an NDES Server via the SCEP Protocol.
    This works on Windows 8.1 and newer Operating Systems.

    .PARAMETER ComputerName
    Specifies the Host Name or IP Address of the NDES Server.
    If using SSL, this must match the NDES Server's identity as specified in its SSL Server Certificate.

    .PARAMETER MachineContext
    By default, the Certificate Request gets created in the current User's Context.
    By specifying this Parameter, it will be created as a Machine Certificate.
    You must execute the Command with Elevation (Run as Administrator) then.

    .PARAMETER Subject
    Specifies the Subject DN for the Certificate.
    May be left empty if you specify a DnsName or Upn instead.

    .PARAMETER DnsName
    Specifies one or more DNS Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject or Upn instead.

    .PARAMETER Upn
    Specifies one or more User Principal Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
    May be left Empty if you specify a Subject or DnsName instead.

    .PARAMETER ChallengePassword
    Specifies the Challenge Password used to authenticate to the NDES Server.
    Not necessary if the NDES Server doesn't require a Password, or if you specify a SigningCert.

    .PARAMETER SigningCert
    Specifies the Signing Certificate used to sign the SCEP Certificate Request.
    Can be passed to the Command via the Pipeline.
    Use this when you already have a Certificate issued by the NDES Server and just want to renew it.
    Subject Information will be taken from this Certificate as otherwise NDES would deny the Request if there is a mismatch.

    .PARAMETER KeyStorageProvider
    Specifies the Cryptographic Service Provider (CSP) or Key Storage Provider (KSP) to be used for the Private Key of the Certificate.
    You can specify any CSP or KSP that is installed on the System.
    Defaults to the Microsoft Software Key Storage Provider.

    .PARAMETER KeyLength
    Specifies the Key Length for the Key pair of the Certificate.
    Defaults to 2048 Bits RSA. ECC is not implemented as of now.

    .PARAMETER PrivateKeyExportable
    Specifies if the Private Key of the Certificate shall be marked as exportable.
    Defaults to the Key being not marked as exportable.

    .PARAMETER UseSSL
    Forces the connection to use SSL Encryption. Not necessary from a security perspective,
    as the SCEP Message's confidential partsd are encrypted with the NDES RA Certificates anyway.

    .PARAMETER Port
    Specifies the Network Port of the NDES Server to be used.
    Only necessary if your NDES Server is running on a non-default Port for some reason.
    Defaults to Port 80 without SSL and 443 with SSL.

    .PARAMETER Method
    Specifies if the Certificate Submission shall be done with HTTP "GET" or "POST".
    Defaults to "POST".

    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate. Returns the issued Certificate returned by the NDES Server.
#>
Function Get-NDESCertificate {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [String]
        $ComputerName,

        [Parameter(ParameterSetName="NewRequest",Mandatory=$False)]
        [Switch]
        $MachineContext = $False,

        [Parameter(ParameterSetName="NewRequest",Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Subject,

        [Parameter(ParameterSetName="NewRequest",Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_ | ForEach-Object -Process {
            [System.Uri]::CheckHostName($_) -eq [System.UriHostnameType]::Dns
        }})]
        [String[]]
        $DnsName,

        [Parameter(ParameterSetName="NewRequest",Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [mailaddress[]]
        $Upn,

        [Parameter(ParameterSetName="NewRequest",Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ChallengePassword,

        [Parameter(
            ParameterSetName="RenewalRequest",
            ValuefromPipeline = $True,
            Mandatory=$False
            )]
        [ValidateScript({$_.HasPrivateKey})]
        [System.Security.Cryptography.X509Certificates.X509Certificate]
        $SigningCert,

        [Parameter(Mandatory=$False)]
        [ValidateScript({Test-KSPAvailability -Name $_})]
        [String]
        $KeyStorageProvider = "Microsoft Software Key Storage Provider",

        [Parameter(Mandatory=$False)]
        [ValidateSet(1024,2048,3072,4096)]
        [Int]
        $KeyLength = 2048,

        [Parameter(Mandatory=$False)]
        [Switch]
        $PrivateKeyExportable = $False,

        [Parameter(Mandatory=$False)]
        [Switch]
        $UseSSL = $False,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,65535)]
        [Int]
        $Port,

        [Parameter(Mandatory=$False)]
        [ValidateSet("GET","POST")]
        [String]
        $Method = "POST"
    )

    begin  {

        New-Variable -Option Constant -Name CR_OUT_BASE64 -Value 1
        New-Variable -Option Constant -Name CR_IN_BASE64HEADER -Value 0
        New-Variable -Option Constant -Name CR_IN_BASE64 -Value 1

        New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64HEADER -Value 0
        New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1
        New-Variable -Option Constant -Name XCN_CRYPT_STRING_BINARY -Value 2
        New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64REQUESTHEADER -Value 3
        New-Variable -Option Constant -Name XCN_CRYPT_STRING_HEX -Value 4

        New-Variable -Option Constant -Name PROPTYPE_BINARY -Value 3
        New-Variable -Option Constant -Name FR_PROP_FULLRESPONSE -Value 1

        New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3
        New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Value 11

        New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_8_1 -Value 9600
        New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_10 -Value 10240

        # https://docs.microsoft.com/en-us/windows/win32/api/certpol/ne-certpol-x509scepdisposition
        New-Variable -Option Constant -Name SCEPDispositionFailure -Value 2
        New-Variable -Option Constant -Name SCEPDispositionPending -Value 3
        New-Variable -Option Constant -Name SCEPDispositionPendingChallenge -Value 11
        New-Variable -Option Constant -Name SCEPDispositionSuccess -Value 0
        New-Variable -Option Constant -Name SCEPDispositionUnknown -Value -1

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequestpkcs10-initializefromcertificate
        New-Variable -Option Constant -Name InheritDefault -Value 0x00000000
        New-Variable -Option Constant -Name InheritRenewalCertificateFlag -Value 0x00000020
        New-Variable -Option Constant -Name InheritTemplateFlag -Value 0x00000040
        New-Variable -Option Constant -Name InheritSubjectFlag -Value 0x00000080
        New-Variable -Option Constant -Name InheritExtensionsFlag -Value 0x00000100
        New-Variable -Option Constant -Name InheritSubjectAltNameFlag -Value 0x00000200

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509privatekeyverify
        New-Variable -Option Constant -Name X509PrivateKeyVerify_VerifyNone -Value 0
        
        Add-Type -AssemblyName System.Security

        # This hides the Status Indicators of the Invoke-WebRequest Calls later on
        $ProgressPreference = 'SilentlyContinue'

        # https://tools.ietf.org/html/draft-nourse-scep-23#section-3.1.1.4
        $SCEPFailInfo = @(

            @{
                Code = 0
                Message = "badAlg"
                Description = "Unrecognized or unsupported algorithm identifier"
            }
            @{
                Code = 1
                Message = "badMessageCheck"
                Description = "integrity check failed"
            }
            @{
                Code = 2
                Message = "badRequest"
                Description = "transaction not permitted or supported"
            }
            @{
                Code = 3
                Message = "badTime"
                Description = "The signingTime attribute from the PKCS#7 authenticatedAttributes was not sufficiently close to the system time."
            }
            @{
                Code = 4
                Message = "badCertId"
                Description = "No certificate could be identified matching the provided criteria."
            }

        )
    }

    process {

        # Ensuring the Code will be executed on a supported Operating System
        If ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_8_1) {
            Write-Error -Message "This must be executed on Windows 8.1/Windows Server 2012 R2 or newer!"
            Return 
        }

        # Ensuring we work with Elevation when messing with the Computer Certificate Store
        If ($MachineContext.IsPresent -or ($SigningCert -and ($SigningCert.PSBase -match "Machine"))) {

            If (-not (
                [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                Write-Error -Message "This must be run with Elevation (Run as Administrator) when using the Machine Context!" 
                return
            }
        }

        # Assembling the Configuration String, which is the SCEP URL in this Case
        If ($UseSSL)
            { $Protocol = "https" }
        Else 
            { $Protocol = "http" }

        If ($Port)
            { $PortString = ":$($Port)" }
        Else
            { $PortString = [String]::Empty }

        # Obviously, this limits the Enrollment to the NDES Role
        # As there are other SCEP Implementations out there, we should perhaps implement 
        # a Suffix or similar parameter to alter the URL for other SCEP Implementations
        $ConfigString = "$($Protocol)://$($ComputerName)$($PortString)/certsrv/mscep/mscep.dll/pkiclient.exe"

        Write-Verbose -Message "Configuration String: $ConfigString"

        # GetCACaps Operation
        # Invoke-WebRequest -uri "$($ConfigString)?operation=GetCACaps" or
        # GetCAProperty with the CR_PROP_SCEPSERVERCAPABILITIES PropId
        # There is also a Method put_ServerCapabilities which maybe can be fed with the output
        Try {
            $GetCACaps = (Invoke-WebRequest -uri "$($ConfigString)?operation=GetCACaps").Content
        }
        Catch {
            Write-Error -Message $PSItem.Exception
            return
        }

        $Pkcs10 = New-Object -ComObject "X509Enrollment.CX509CertificateRequestPkcs10"

        # Determining if we create an entirely new Certificate Request or inherit Settings from an old one
        If ($SigningCert) {

            If ($GetCACaps -match "Renewal") {

                $X509RequestInheritOptions = $InheritDefault
                $X509RequestInheritOptions += $InheritSubjectAltNameFlag
                $X509RequestInheritOptions += $InheritExtensionsFlag
                $X509RequestInheritOptions += $InheritSubjectFlag

                $Pkcs10.InitializeFromCertificate(
                    ([Int]($SigningCert.PSBase -match "Machine") +1), # match to the old Cert's Store
                    [Convert]::ToBase64String($SigningCert.RawData),
                    $XCN_CRYPT_STRING_BASE64,
                    $X509RequestInheritOptions
                )

                <#
                    https://tools.ietf.org/html/draft-nourse-scep-23#section-2.3
                    A client that is performing certificate renewal as per Appendix D
                    SHOULD send an empty challenge password (i.e. use the empty string as
                    the challenge password) but MAY send the originally distributed
                    challenge password in the challengePassword attribute.
                #>
                $Pkcs10.ChallengePassword = [String]::Empty

            }
            Else {
                Write-Error -Message "The Server does not support Renewal!"
                return
            }

        }
        Else {

            If ((-not $DnsName) -and (-not $Upn) -and ((-not $Subject) -or ($Subject -eq "CN="))) {
                Write-Error -Message "You must provide an Identity, either in Form ob a Subject or Subject Alternative Name!"
                return
            }

            $Pkcs10.Initialize([int]($MachineContext.IsPresent)+1)

            Try {
                # To Do: implement Validation of the Subject RDN
                $DnObject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
                $DnObject.Encode($Subject)
                $Pkcs10.Subject = $DnObject
            }
            Catch {
                Write-Error -Message "Invalid Subject DN supplied!"
                return
            }

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

            If ($ChallengePassword) {
                <#
                    https://tools.ietf.org/html/draft-nourse-scep-23#section-2.2
                    PKCS#10 [RFC2986] specifies a PKCS#9 [RFC2985] challengePassword
                    attribute to be sent as part of the enrollment request.  Inclusion of
                    the challengePassword by the SCEP client is OPTIONAL and allows for
                    unauthenticated authorization of enrollment requests.
                #>
                $Pkcs10.ChallengePassword = $ChallengePassword
            }

        }

        # Configuring the private Key of the Certificate
        $Pkcs10.PrivateKey.Length = $KeyLength
        $Pkcs10.PrivateKey.ExportPolicy = [int]($PrivateKeyExportable.IsPresent)
        $Pkcs10.PrivateKey.ProviderName = $KeyStorageProvider

        # SCEP GetCACert Operation
        Try {
            $GetCACert = (Invoke-WebRequest -uri "$($ConfigString)?operation=GetCACert").Content
        }
        Catch {
            Write-Error -Message $PSItem.Exception
            return
        }

        # Decoding the CMS (PKCS#7 Message that was returned from the NDES Server)
        $Pkcs7CaCert = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $Pkcs7CaCert.Decode($GetCACert)
        
        # Identify the Root CA Certificate that was delivered with the Chain
        # We must specify it's MD5 Hash when initializing the IX509SCEPEnrollment Interface
        $RootCaCert = $Pkcs7CaCert.Certificates | Where-Object { $_.Subject -eq $_.Issuer }

        # Initialize the IX509SCEPEnrollment Interface
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509scepenrollment
        $SCEPEnrollmentInterface = New-Object -ComObject "X509Enrollment.CX509SCEPEnrollment"

        # Let's try to build a SCEP Enrollment Message now...

        Try {

            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-initialize
            $SCEPEnrollmentInterface.Initialize(
                $Pkcs10,
                (Get-HashValue -Bytes $RootCaCert.RawData -HashAlgorithm "MD5"), # no Joke... MD5...
                $XCN_CRYPT_STRING_HEX,
                [Convert]::ToBase64String($GetCACert),
                $XCN_CRYPT_STRING_BASE64
            )

        }
        Catch {
            Write-Error -Message $PSItem.Exception
            return
        }

        # Sets the preferred hash and encryption algorithms for the request.
        # If you do not set this property, then the default hash and encryption algorithms will be used.
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-put_servercapabilities
        $SCEPEnrollmentInterface.ServerCapabilities = $GetCACaps

        <#
            https://tools.ietf.org/html/draft-nourse-scep-23#section-2.2
            If the requester does not have an appropriate existing
            certificate, then a locally generated self-signed certificate
            MUST be used instead.  The self-signed certificate MUST use the
            same subject name as in the PKCS#10 request.

            https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-put_signercertificate
            To create a renewal request, you must set this property prior to calling the CreateRequestMessage method. 
            Otherwise, the CreateRequestMessage method will create a new request and generate a self-signed certificate 
            using the same private key as the inner PKCSV10 reqeust.
        #>
        If ($SigningCert) {

            $SignerCertificate = New-Object -ComObject 'X509Enrollment.CSignerCertificate'

            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-isignercertificate-initialize
            $SignerCertificate.Initialize(
                [Int]($SigningCert.PSBase -match "Machine"), # 0 = User, 1 = Machine
                $X509PrivateKeyVerify_VerifyNone, # We did this during Parameter Validation
                $XCN_CRYPT_STRING_BASE64,
                [Convert]::ToBase64String($SigningCert.RawData)
            )
            $SCEPEnrollmentInterface.SignerCertificate = $SignerCertificate
        }

        # Building the PKCS7 Message for the SCEP Enrollment
        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-createrequestmessage
        $SCEPRequestMessage = $SCEPEnrollmentInterface.CreateRequestMessage($XCN_CRYPT_STRING_BASE64)
        
        # Submission to the NDES Server
        try {

            If ($Method -eq "POST") {

                If ($GetCACaps -match "POSTPKIOperation") {
                    $SCEPResponse = Invoke-WebRequest `
                        -Body ([Convert]::FromBase64String($SCEPRequestMessage)) `
                        -Method 'POST' `
                        -Uri "$($ConfigString)?operation=PKIOperation" `
                        -Headers @{'Content-Type' = 'application/x-pki-message'}
                }
                Else {
                    Write-Warning -Message "The Server indicates that it doesnt support the 'POST' Method. Falling back to 'GET'."
                    $Method = "GET"
                }
            }

            If ($Method -eq "GET") {
                $SCEPResponse = Invoke-WebRequest `
                    -Method 'GET' `
                    -Uri "$($ConfigString)?operation=PKIOperation&message=$([uri]::EscapeDataString($SCEPRequestMessage))" `
                    -Headers @{'Content-Type' = 'application/x-pki-message'}
            }

            $SCEPResponse = [Convert]::ToBase64String($ScepResponse.Content)

        }
        catch {
            Write-Error -Message $PSItem.Exception
            return
        }
        
        Try {

            # Process a response message and return the disposition of the message.
            # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-processresponsemessage
            $Disposition = $SCEPEnrollmentInterface.ProcessResponseMessage(
                $SCEPResponse,
                $XCN_CRYPT_STRING_BASE64
                )

            # https://docs.microsoft.com/en-us/windows/win32/api/certpol/ne-certpol-x509scepdisposition
            Switch ($Disposition) {

                $SCEPDispositionFailure {

                    $ErrorMessage = ''
                    $ErrorMessage += "The NDES Server rejected the Certificate Request!`n"

                    # The Failinfo Method is only present in Windows 10
                    # Windows 8.1 / 2012 R2 Users therefore won't get any fancy error message, sadly
                    If ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -ge $BUILD_NUMBER_WINDOWS_10) {

                        $FailInfo = ($SCEPFailInfo | Where-Object { $_.Code -eq $SCEPEnrollmentInterface.FailInfo() })

                        $ErrorMessage += "SCEP Failure Information: $($FailInfo.Message) ($($FailInfo.Code)) $($FailInfo.Description)`n"
                        $ErrorMessage += "Additional Information returned by the Server: $($SCEPEnrollmentInterface.Status().Text)`n"

                        # CERT_E_WRONG_USAGE
                        If ($SCEPEnrollmentInterface.Status().Text -match "0x800b0110") {
                            $ErrorMessage += "Possible reason(s): The Challenge Password has already been used before."
                        }

                        # TRUST_E_CERT_SIGNATURE
                        If ($SCEPEnrollmentInterface.Status().Text -match "0x80096004") {
                            $ErrorMessage += "Possible reason(s): The NDES Server requires a Challenge Password but none was supplied."
                        }

                        # ERROR_NOT_FOUND
                        If ($SCEPEnrollmentInterface.Status().Text -match "0x80070490") {
                            $ErrorMessage += "Possible reason(s): The Challenge Password supplied is unknown to the NDES Server."
                        }

                        # CERTSRV_E_BAD_REQUESTSUBJECT
                        If ($SCEPEnrollmentInterface.Status().Text -match "0x80094001") {
                            $ErrorMessage += "Possible reason(s): The CA denied your request because an invalid Subject was requested."
                        }

                        # RPC_S_SERVER_UNAVAILABLE
                        If ($SCEPEnrollmentInterface.Status().Text -match "0x800706ba") {
                            $ErrorMessage += "Possible reason(s): The NDES Server was unable to contact the Certification Authority."
                        }
                    }

                    Write-Error -Message $ErrorMessage

                }

                $SCEPDispositionSuccess {

                    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-get_certificate
                    $CertificateBase64 = $SCEPEnrollmentInterface.Certificate($XCN_CRYPT_STRING_BASE64)

                    # We load the Certificate into an X509Certificate2 Object
                    $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $CertificateObject.Import([Convert]::FromBase64String($CertificateBase64))

                    # We return this to the User
                    $CertificateObject
                }

                $ScepDispositionPending {
                    Write-Warning -Message "The Enrollment was successful with Status ScepDispositionPending, which is not yet implemented!"
                }

                $ScepDispositionPendingChallenge {
                    Write-Warning -Message  "The Enrollment was successful with Status ScepDispositionPendingChallenge, which is not yet implemented!"
                }

                $SCEPDispositionUnknown {
                    Write-Error -Message "The Enrollment failed for an unknown Reason"
                }

            }

        }
        Catch {
            Write-Error -Message $PSItem.Exception
            return  
        }

        # Cleaning up the COM Objects, avoiding any User Errors to be reported
        $Pkcs10,
        $DnObject,
        $SansExtension,
        $Sans,
        $SCEPEnrollmentInterface,
        $SignerCertificate | ForEach-Object -Process {

            try{
                [void](System.Runtime.Interopservices.Marshal]::ReleaseComObject($_))
            }
            catch {
                # we don't want to return anything here
            }
        }
    }
}