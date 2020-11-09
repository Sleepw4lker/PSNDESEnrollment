
[cmdletbinding()]
param(
    [Parameter(Mandatory=$True)]
    [String]
    $ComputerName,

    [Parameter(Mandatory=$False)]
    [ValidateSet(1024,2048,3072,4096)]
    [Int]
    $KeyLength = 2048,

    [Parameter(ParameterSetName="NewRequest",Mandatory=$False)]
    [Switch]
    $MachineContext = $False,

    [Parameter(ParameterSetName="NewRequest",Mandatory=$False)]
    [String]
    $Subject = "CN=",

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

    [Parameter(ParameterSetName="RenewalRequest",Mandatory=$False)]
    [ValidateScript({$_.HasPrivateKey})]
    [X509Certificate]
    $SigningCert,

    [Parameter(Mandatory=$False)]
    [Switch]
    $UseSSL = $False,

    [Parameter(Mandatory=$False)]
    [ValidateSet("GET","POST")]
    [String]
    $Method = "POST"
)

begin  {

    New-Variable -Option Constant -Name CR_OUT_BASE64 -Value 1
    New-Variable -Option Constant -Name CR_IN_BASE64HEADER -Value 0
    New-Variable -Option Constant -Name CR_IN_BASE64 -Value 1
    New-Variable -Option Constant -Name CR_IN_PKCS7 -Value 0x300
    New-Variable -Option Constant -Name CR_IN_SCEP -Value 0x00010000
    New-Variable -Option Constant -Name CR_IN_SCEPPOST -Value 0x02000000

    New-Variable -Option Constant -Name CR_PROP_SCEPSERVERCERTS -Value 1000
    New-Variable -Option Constant -Name CR_PROP_SCEPSERVERCAPABILITIES -Value 1001

    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64HEADER -Value 0
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BINARY -Value 2
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64REQUESTHEADER -Value 3
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_HEX -Value 4
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_HEXRAW -Value 12

    New-Variable -Option Constant -Name PROPTYPE_BINARY -Value 3
    New-Variable -Option Constant -Name FR_PROP_FULLRESPONSE -Value 1

    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Value 11

    New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_8_1 -Value 9600

    Add-Type -AssemblyName System.Security

    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509certificaterequestpkcs10-initializefromcertificate
    New-Variable -Option Constant -Name InheritDefault -Value 0x00000000
	New-Variable -Option Constant -Name InheritRenewalCertificateFlag -Value 0x00000020
	New-Variable -Option Constant -Name InheritTemplateFlag -Value 0x00000040
	New-Variable -Option Constant -Name InheritSubjectFlag -Value 0x00000080
	New-Variable -Option Constant -Name InheritExtensionsFlag -Value 0x00000100
	New-Variable -Option Constant -Name InheritSubjectAltNameFlag -Value 0x00000200
}

process {

    Function Get-HashValue {
        [cmdletbinding()]
        param(
            [Byte[]]
            $Bytes,
    
            [String]
            [ValidateSet("MD5","SHA1","SHA256","SHA512")]
            $HashAlgorithm = "SHA1"
        )
    
        $HashAlgorithmObject = [System.Security.Cryptography.HashAlgorithm]::Create($HashAlgorithm)
        $Hash = $HashAlgorithmObject.ComputeHash($Bytes)

        $Hashhex = ''
        $Hash | ForEach-Object -Process { 
            $Hashhex += $_.ToString("X") 
        }
        return $Hashhex
    }

    # Ensuring the Code will be executed on a supported Operating System
    If ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_8_1) {
        Write-Error "This must be executed on Windows 8.1 or newer! Aborting."
        Return 
    }

    # Ensuring we work with Elevation when messing with the Computer Certificate Store
    If ($MachineContext.IsPresent -or ($SigningCert -and ($SigningCert.PSBase -match "Machine"))) {

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

    # Determining if we create an entirely new Certificate Request or inherit Settings from an old one
    If ($SigningCert) {

        $X509RequestInheritOptions = $InheritDefault
        $X509RequestInheritOptions += $InheritSubjectAltNameFlag
        $X509RequestInheritOptions += $InheritExtensionsFlag
        $X509RequestInheritOptions += $InheritSubjectFlag

        $Pkcs10.InitializeFromCertificate(
            ([Int]($SigningCert.PSBase -match "Machine") +1), # match to the old Cert's Store
            [Convert]::ToBase64String($SigningCert.RawData),
            $XCN_CRYPT_STRING_BASE64,
            $X509RequestInheritOptions)

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

        $Pkcs10.Initialize([int]($MachineContext.IsPresent)+1)

        Try {
            # To Do: implement Validation of the Subject RDN
            $DnObject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
            $DnObject.Encode($Subject)
            $Pkcs10.Subject = $DnObject
        }
        Catch {
            #
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

    $Pkcs10.PrivateKey.Length = $KeyLength

    # Initializing the Request Interface that does Submission and Retrieval
    $CertRequestInterface = New-Object -ComObject "CertificateAuthority.Request"

    <#
        Maybe we need this later on...
        GetCACaps Operation
        Invoke-WebRequest -uri "$ConfigString/mscep.dll/pkiclient.exe?operation=GetCACaps" or
        GetCAProperty with the CR_PROP_SCEPSERVERCAPABILITIES PropId
    #>

    # SCEP GetCACert Operation
    Try {
        $GetCACert = $CertRequestInterface.GetCAProperty(
            $ConfigString,
            $CR_PROP_SCEPSERVERCERTS,
            0,
            $PROPTYPE_BINARY,
            $CR_OUT_BASE64
        )
    }
    Catch {
        Write-Error $PSItem.Exception
        return
    }

    $Pkcs7CaCert = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $Pkcs7CaCert.Decode([Convert]::FromBase64String($GetCACert))
    
    # Identify the Root CA Certificate that was delivered with the Chain
    $RootCA = $Pkcs7CaCert.Certificates | Where-Object {$_.Subject -eq $_.Issuer }

    # Initialize the IX509SCEPEnrollment Interface
    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509scepenrollment
    $SCEPEnrollment = New-Object -ComObject "X509Enrollment.CX509SCEPEnrollment"

    Try {

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-initialize
        $SCEPEnrollment.Initialize(
            $Pkcs10,
            (Get-HashValue -Bytes $RootCA.RawData -HashAlgorithm "MD5"), # no Joke... MD5...
            $XCN_CRYPT_STRING_HEX,
            $GetCACert,
            $XCN_CRYPT_STRING_BASE64
        )

    }
    Catch {
        Write-Error $PSItem.Exception
        return
    }

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
            0, # MachineContext
            0, # X509PrivateKeyVerify
            $XCN_CRYPT_STRING_BASE64,
            [Convert]::ToBase64String($SigningCert.RawData)
        )
        $SCEPEnrollment.SignerCertificate = $SignerCertificate
    }

    # Building the PKCS7 Message for the SCEP Enrollment
    # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-createrequestmessage
    $TheRequest = $SCEPEnrollment.CreateRequestMessage($XCN_CRYPT_STRING_BASE64)

    # Submission to the NDES Server
    $RequestFlags = $CR_IN_BASE64
    $RequestFlags = $RequestFlags -bor $CR_IN_SCEP

    If ($Method -eq "POST") {
        $RequestFlags = $RequestFlags -bor $CR_IN_SCEPPOST
    }

    Try {
        [void]($CertRequestInterface.Submit(
            $RequestFlags,
            $TheRequest,
            "",
            $ConfigString
        ))
    }
    Catch {
        Write-Error $PSItem.Exception
        return  
    }

    Try {

        # Here's where we get the Certificate from
        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest2-getfullresponseproperty
        $TheSCEPResponse = $CertRequestInterface.GetFullResponseProperty(
            $FR_PROP_FULLRESPONSE,
            0,
            $PROPTYPE_BINARY,
            $CR_OUT_BASE64
        )
        # Perhaps we can also use this to determine the actual Status of the Request

        [void]($SCEPEnrollment.ProcessResponseMessage(
            $TheSCEPResponse,
            $XCN_CRYPT_STRING_BASE64
            ))

        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509scepenrollment-get_certificate
        $CertificateBase64 = $SCEPEnrollment.Certificate($XCN_CRYPT_STRING_BASE64)

        # We load the Certificate into an X509Certificate2 Object
        $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $CertificateObject.Import([Convert]::FromBase64String($CertificateBase64))
        $CertificateObject

    }
    Catch {
        Write-Error $PSItem.Exception
        return  
    }
}