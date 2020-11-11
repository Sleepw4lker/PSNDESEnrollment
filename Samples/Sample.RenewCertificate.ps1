$IssuingCaName = "ADCS Labor Issuing CA 1"
$NdesServerName = "ndes.adcslabor.de"
$RenewalPeriodDays = 90
$CertificateStore = Get-ChildItem -Path Cert:\CurrentUser\My
$ServerAuthentication = "1.3.6.1.5.5.7.3.1"

Import-Module PSNDESEnrollment

# Identify expiring Certificate based on the defined criteria
$OldCert = $CertificateStore | Where-Object {
    ($_.IssuerName.Name -match $IssuingCaName) -and
    ($_.EnhancedKeyUsageList -contains $ServerAuthentication) -and 
    ($_.NotAfter -lt $(Get-Date).AddDays($RenewalPeriodDays))
} | Sort-Object -Property NotAfter -Ascending | 
        Select-Object -First 1

# Request new Certificate
If ($OldCert) {
    $NewCert = $OldCert | Get-NDESCertificate -ComputerName $NdesServerName
}

# Archive the old Certificate if renewal was successful
If ($NewCert) {
    $OldCert.Archived = $True
}