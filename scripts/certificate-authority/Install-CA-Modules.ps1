[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)]
    [string]$CRLS3BucketName,

    [Parameter(Mandatory = $true)]
    [string]$Region,

    [Parameter(Mandatory = $true)]
    [string]$HostName
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

"Setting up Powershell Gallery to Install DSC Modules"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5 -Force
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

"Installing the needed Powershell DSC modules for the CA instances"
Install-Module -Name NetworkingDsc -RequiredVersion 8.0.0
Install-Module -Name ActiveDirectoryDsc -RequiredVersion 6.0.1
Install-Module -Name ComputerManagementDsc -RequiredVersion 8.4.0
Install-Module -Name xDnsServer -RequiredVersion 1.16.0.0
Install-Module -Name ActiveDirectoryCSDsc -RequiredVersion 5.0.0
Install-Module -Name xActiveDirectory -RequiredVersion 2.21.0.0
Install-Module -Name xPSDesiredStateConfiguration -RequiredVersion 9.1.0
Install-Module -Name ADCSTemplate

"Disabling Windows Firewall"
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False

"Creating Directory for DSC Public Cert"
New-Item -Path C:\CWE\publickeys -ItemType directory 

"Setting up DSC Certificate to Encrypt Credentials in MOF File"
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp -DnsName "$($HostName)-DscEncryptCert" -HashAlgorithm SHA256

"Exporting the public key certificate"
$cert | Export-Certificate -FilePath "C:\CWE\publickeys\$($HostName)-DscPublicKey.cer" -Force

"Uploading the public key to S3"
Write-S3Object -BucketName publickeys -File "C:\CWE\publickeys\$($HostName)-DscPublicKey.cer" -Key "$($HostName)-DscPublicKey.cer" -Endpoint "https://$($CRLS3BucketName).s3-fips.$($Region).amazonaws.com" -Region $Region
