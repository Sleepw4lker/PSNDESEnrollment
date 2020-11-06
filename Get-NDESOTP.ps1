[cmdletbinding()]
param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ComputerName,

    [Parameter(Mandatory=$False)]
    [Switch]
    $UseSSL = $False,

    [Parameter(Mandatory=$False)]
    [Int]
    $PasswordLength = 8, # Sadly, this must be adjusted if not using the default values on the Server

    [Parameter(Mandatory=$False)]
    [PSCredential]
    $Credential
)

If ($UseSSL)
    { $Protocol = "https" }
Else 
    { $Protocol = "http" }

$ConfigString = "$($Protocol)://$($ComputerName)/certsrv/mscep_admin"

try {

    If ($Credential) {
        # HTTP Basic Authentication, needs to be specifically enabled on the NDES Server
        $WebRequest = Invoke-WebRequest -Uri $ConfigString -Credential $Credential
    }
    Else {
        # Try Windows integrated Authentication
        $WebRequest = Invoke-WebRequest -Uri $ConfigString -UseDefaultCredentials
    }

}
catch {
    #
}

If ($WebRequest) {

    # Convert the HTML Output (Contains a Byte Order mark, probably UTF-16 LE encoded) to Unicode
    $HTML = [system.Text.Encoding]::Unicode.GetString($WebRequest.RawContentStream.ToArray())

    # Grab the Password from the HTML Output
    return $($HTML | Select-String -Pattern "[A-F0-9]{$($PasswordLength*2)}" -AllMatches | 
        ForEach-Object -Process { $_.Matches } | 
            ForEach-Object -Process { $_.Value } | 
                Select-Object -First 1)

}