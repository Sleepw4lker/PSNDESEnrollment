---
external help file: PSNDESEnrollment-help.xml
Module Name: PSNDESEnrollment
online version:
schema: 2.0.0
---

# Get-NDESCertificate

## SYNOPSIS
Requests a Certificate from an NDES Server via the SCEP Protocol.
This works on Windows 8.1 and newer Operating Systems.

## SYNTAX

### NewRequest
```
Get-NDESCertificate -ComputerName <String> [-MachineContext] [-Subject <String>] [-DnsName <String[]>]
 [-Upn <MailAddress[]>] [-ChallengePassword <String>] [-KeyStorageProvider <String>] [-KeyLength <Int32>]
 [-PrivateKeyExportable] [-UseSSL] [-Port <Int32>] [-Method <String>] [<CommonParameters>]
```

### RenewalRequest
```
Get-NDESCertificate -ComputerName <String> [-SigningCert <X509Certificate>] [-KeyStorageProvider <String>]
 [-KeyLength <Int32>] [-PrivateKeyExportable] [-UseSSL] [-Port <Int32>] [-Method <String>] [<CommonParameters>]
```

## DESCRIPTION
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -ComputerName
Specifies the Host Name or IP Address of the NDES Server.
If using SSL, this must match the NDES Server's identity as specified in its SSL Server Certificate.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -MachineContext
By default, the Certificate Request gets created in the current User's Context.
By specifying this Parameter, it will be created as a Machine Certificate.
You must execute the Command with Elevation (Run as Administrator) then.

```yaml
Type: SwitchParameter
Parameter Sets: NewRequest
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Subject
Specifies the Subject DN for the Certificate.
May be left empty if you specify a DnsName or Upn instead.

```yaml
Type: String
Parameter Sets: NewRequest
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DnsName
Specifies one or more DNS Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
May be left Empty if you specify a Subject or Upn instead.

```yaml
Type: String[]
Parameter Sets: NewRequest
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Upn
Specifies one or more User Principal Names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.
May be left Empty if you specify a Subject or DnsName instead.

```yaml
Type: MailAddress[]
Parameter Sets: NewRequest
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ChallengePassword
Specifies the Challenge Password used to authenticate to the NDES Server.
Not necessary if the NDES Server doesn't require a Password, or if you specify a SigningCert.

```yaml
Type: String
Parameter Sets: NewRequest
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SigningCert
Specifies the Signing Certificate used to sign the SCEP Certificate Request.
Can be passed to the Command via the Pipeline.
Use this when you already have a Certificate issued by the NDES Server and just want to renew it.
Subject Information will be taken from this Certificate as otherwise NDES would deny the Request if there is a mismatch.

```yaml
Type: X509Certificate
Parameter Sets: RenewalRequest
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -KeyStorageProvider
Specifies the Cryptographic Service Provider (CSP) or Key Storage Provider (KSP) to be used for the Private Key of the Certificate.
You can specify any CSP or KSP that is installed on the System.
Defaults to the Microsoft Software Key Storage Provider.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: Microsoft Software Key Storage Provider
Accept pipeline input: False
Accept wildcard characters: False
```

### -KeyLength
Specifies the Key Length for the Key pair of the Certificate.
Defaults to 2048 Bits RSA.
ECC is not implemented as of now.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 2048
Accept pipeline input: False
Accept wildcard characters: False
```

### -PrivateKeyExportable
Specifies if the Private Key of the Certificate shall be marked as exportable.
Defaults to the Key being not marked as exportable.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -UseSSL
Forces the connection to use SSL Encryption.
Not necessary from a security perspective,
as the SCEP Message's confidential partsd are encrypted with the NDES RA Certificates anyway.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Port
Specifies the Network Port of the NDES Server to be used.
Only necessary if your NDES Server is running on a non-default Port for some reason.
Defaults to Port 80 without SSL and 443 with SSL.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Method
Specifies if the Certificate Submission shall be done with HTTP "GET" or "POST".
Defaults to "POST".

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: POST
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Security.Cryptography.X509Certificates.X509Certificate
### The issued Certificate returned by the NDES Server.
## NOTES

## RELATED LINKS
