$NdesServerName = "ndes.adcslabor.de"
$CommonName = "TestNDESCert"

Import-Module PSNDESEnrollment

$Otp = Get-NDESOTP -ComputerName $NdesServerName

Get-NDESCertificate `
    -ComputerName $NdesServerName `
    -Subject "CN=$CommonName" `
    -ChallengePassword $Otp `
    -PrivateKeyExportable