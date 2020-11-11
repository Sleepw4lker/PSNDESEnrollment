Function Get-HashValue {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [Byte[]]
        $Bytes,

        [Parameter(Mandatory=$False)]
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512")]
        [String]
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