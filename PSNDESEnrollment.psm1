$ModuleRoot = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

. $ModuleRoot\Functions\Get-NDESOTP.ps1
. $ModuleRoot\Functions\Get-NDESCertificate.ps1
. $ModuleRoot\Functions\Test-KSPAvailability.ps1