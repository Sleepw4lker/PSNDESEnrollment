# PSNDESEnrollment

PowerShell Module to request One-Time Password (OTP) from a Network Device Enrollment Service (NDES) and then to enroll for a User or Machine Certificate.

Supports Windows 8.1 / Windows Server 2012 R2 or newer.

Contains the following functions:
* [Get-NDESOTP](docs/Get-NDESOTP.md)
* [Get-NDESCertificate](docs/Get-NDESCertificate.md)

## Get-NDESOTP
Retrieves an One-Time-Password (OTP) from the NDES Server.

Uses SSL by default. SSL can be disabled if required, but this is not recommended.

Uses your Windows Identity by default but can also be passed a PSCredential Object (Get-Credential).

The -PasswordLength Parameter must be adjusted if you do not use the default 8-Character Passwords on the NDES (as it's only RegEx grabbing the HTML Output).

## Get-NDESCertificate
Creates, Submits and Retrieves an NDES Certificate Request using the IX509SCEPEnrollment Interface available in Windows 8.1 and higher.

Supports Renewal Mode.

Supports SSL, but doesnt use it by default (not necessary as sensitive Data is protected anyway).