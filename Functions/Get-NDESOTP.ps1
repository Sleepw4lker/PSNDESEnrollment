<#
    .SYNOPSIS
    Requests an One-Time Password from an NDES Server.

    .PARAMETER ComputerName
    Specify the Host Name or IP Address of the NDES Server.
    Make sure that this matches with the SSL Certificate on the NDES Server, or disable SSL with the -NoSSL Argument (not recommended).

    .PARAMETER NoSSL
    Forces the connection to not use SSL Encryption, which is not recommended.
    Warning: Credentials will be sent in clear-text over the wire!

    .PARAMETER PasswordLength
    If the NDES Server does not use the default Password Length of 8 Characters, adjust to Server Setting with this parameter.
    Getting the Enrollment Challenge Password is basically just grabbing the HTML Output of the Website.

    .PARAMETER Credential
    By default, we use the Credential of the logged-on user.
    You can specify a Credential (Get-Credential) with this Argument to force usage of HTTP Basic Authentication.
    HTTP Basic Authentication must be supported by the NDES Server.

    .OUTPUTS
    System.String. Returns the One-Time password generated by NDES.
#>
Function Get-NDESOTP {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName,

        [Parameter(Mandatory=$False)]
        [Switch]
        $NoSSL = $False,

        [Parameter(Mandatory=$False)]
        [Int]
        $PasswordLength = 8,

        [Parameter(Mandatory=$False)]
        [PSCredential]
        $Credential
    )

    If ($NoSSL) { 
        Write-Warning "Not using SSL. Authentication Credentials will be sent in Cleartext"
        $Protocol = "http" 
    }
    Else {
        $Protocol = "https" 
    }

    $Arguments = @{
        Uri = "$($Protocol)://$($ComputerName)/certsrv/mscep_admin/"
    }

    If ($Credential) {
        $Arguments.Add("Credential", $Credential)
    }
    Else {
        # Use Windows integrated Authentication
        $Arguments.Add("UseDefaultCredentials", $True)
    }

    Try {
        $NdesResponse = Invoke-WebRequest @Arguments
    }
    Catch {
        Write-Error -Message $PSItem.Exception
        return
    }

    If ($NdesResponse) {
        
        switch ($NdesResponse.StatusCode) {
         
            200 {
                # Convert the HTML Output (contains a Byte Order mark, probably UTF-16 LE encoded) to Unicode
                $HTML = [System.Text.Encoding]::Unicode.GetString($NdesResponse.RawContentStream.ToArray())

                # Grab the Password from the HTML Output.
                $Otp = $($HTML | Select-String -Pattern "[A-F0-9]{$($PasswordLength*2)}" -AllMatches | 
                    ForEach-Object -Process { $_.Matches } | 
                        ForEach-Object -Process { $_.Value } | 
                            Select-Object -First 1)

                If ($null -eq $Otp) {
                    Write-Warning "No OTP found in HTTP Response. Check your Permissions and the -PasswordLength Parameter."
                }
                Else {
                    return $Otp
                }
            }
            default {
                Write-Error "Got HTTP Response $($NdesResponse.StatusCode)."
            }
        }
    }
}