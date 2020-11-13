# PSNDESEnrollment

PowerShell Module to request or renew a User or Machine Certificate via the [Simple Certificate Enrollment Protocol (SCEP)](https://tools.ietf.org/html/draft-nourse-scep-23). The Microsoft Implementation of SCEP is called Network Device Enrollment Service (NDES), thus the name.

Supported Operating Systems:

* Windows 8.1
* Windows 10
* Windows Server 2012 R2
* Windows Server 2016
* Windows Server 2019

Earlier Operating Systems, PowerShell Core and Linux are not supported, as native OS Interfaces are used that are not present in these.

Supported SCEP Implementations:

* Microsoft Network Device Enrollment Service (NDES)

Other SCEP Implementations should be easy to implement but I currently have none to test against.

The following functions get exported:
* [Get-NDESOTP](docs/Get-NDESOTP.md)
* [Get-NDESCertificate](docs/Get-NDESCertificate.md)

## Get-NDESOTP
Retrieves an One-Time-Password (OTP) from the NDES Server.

Uses SSL by default. SSL can be disabled if required, but this is not recommended.

Uses your Windows Identity by default but can also be passed a PSCredential Object (Get-Credential).

The -PasswordLength Parameter must be adjusted if you do not use the default 8-Character Passwords on the NDES (as it's only RegEx grabbing the HTML Output).

## Get-NDESCertificate
Creates, Submits and Retrieves an NDES Certificate Request using the IX509SCEPEnrollment Interface available in Windows 8.1 and higher.

Supports Renewal Mode by passing an X509Certificate Object either via the Pipeline or the -SigningCertificate Argument. The Certificate must have a private Key, and be issued from the same CA as the new one.

Supports SSL, but doesnt use it by default (not necessary as sensitive Data is protected anyway).