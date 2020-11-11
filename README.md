# PSNDESEnrollment

PowerShell Module to request One-Time Password (OTP) from a Network Device Enrollment Service (NDES) and then to enroll for a User or Machine Certificate. Supports Enrollment over SSL.

Contains the following functions:
* Get-NDESOTP
* Get-NDESCertificate

## Get-NDESOTP
Retrieves an One-Time-Password (OTP) from the NDES Server. Uses SSL by default. Uses your Windows Identity by default but can also be passed a PSCredential Object. PasswordLength must be adjusted if you do not use the default 8-Character Passwords on the NDES (as it's only RegEx grabbing the HTML Output).

## Get-NDESCertificate
Creates, Submits and Retrieves an NDES Certificate Request using the IX509SCEPEnrollment Interface available in Windows 8.1 and higher.

Supports Renewal Mode.

Supports SSL, but doesnt use it by default (not necessary as sensitive Data is protected anyway).