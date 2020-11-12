Import-Module -Name .\PSNDESEnrollment.psd1 -Force
Import-Module -Name platyps -ErrorAction Stop

Update-MarkdownHelp .\docs
New-ExternalHelp .\docs -OutputPath en-US\