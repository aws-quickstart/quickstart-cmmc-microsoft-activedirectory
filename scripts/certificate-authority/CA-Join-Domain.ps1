[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)]
    [string]$LocalAdminSSMParam,

    [Parameter(Mandatory = $true)]
    [string]$DomainAdminSSMParam,

    [Parameter(Mandatory = $true)]
    [string]$DomainDNSName,
    
    [Parameter(Mandatory = $true)]
    [string]$Region,

    [Parameter(Mandatory = $true)]
    [string]$HostName
)

# Get the FIPS endpoint URL
$EndpointUrl = "https://secretsmanager-fips." + $Region + ".amazonaws.com"
# Getting Password from Secrets Manager for CA Admin User
$LocalAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -EndpointUrl $EndpointUrl -SecretId $LocalAdminSSMParam).SecretString
# Creating Credential Object for CA Administrator
$LocalCredentials = (New-Object PSCredential($LocalAdminPassword.UserName, (ConvertTo-SecureString $LocalAdminPassword.Password -AsPlainText -Force)))

# Getting Password from Secrets Manager for Domain Admin User
$ADAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -EndpointUrl $EndpointUrl -SecretId $DomainAdminSSMParam).SecretString
# Formatting Domain Admin User to proper format for JoinDomain DSC Resources in this Script
$DomainAdmin = 'Domain\User' -replace 'Domain', $DomainNetBIOSName -replace 'User', $ADAdminPassword.UserName
# Creating Credential Object for Domain Admin User
$DomainCredentials = (New-Object PSCredential($DomainAdmin, (ConvertTo-SecureString $ADAdminPassword.Password -AsPlainText -Force)))
# Getting the DSC Cert Encryption Thumbprint to Secure the MOF File based on the host name
$DscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | Where-Object { $_.subject -eq "CN=$($HostName)-DscEncryptCert" }).Thumbprint

# Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName             = 'localhost'
            PSDscAllowDomainUser = $true
            CertificateFile      = "C:\CWE\publickeys\$($HostName)-DscPublicKey.cer"
            Thumbprint           = $DscCertThumbprint
        }
    )
}

Configuration CAJoinDomain {
    # Credential Objects being passed in
    param
    (
        [PSCredential] $LocalCredentials,
        [PSCredential] $DomainCredentials
    )
    
    # Importing DSC Modules needed for Configuration
    Import-Module -Name ComputerManagementDsc
    Import-Module -Name xActiveDirectory
    
    # Importing All DSC Resources needed for Configuration
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
  
    
    # Node Configuration block, since processing directly on DC using localhost
    Node 'localhost' {
        # Changing the Local Administrator Password, this account will be a Domain Admin
        User AdministratorPassword {
            UserName = "Administrator"
            Password = $LocalCredentials
        }

        # Wait for the Domain to be available so we can join it.
        xWaitForADDomain DscDomainWait {
            DomainName       = $DomainDNSName
            RetryCount       = 600
            RetryIntervalSec = 30
            RebootRetryCount = 10
        }

        # Join this Server to the Domain and rename it to the new host name
        Computer JoinDomain { 
            Name       = $HostName
            DomainName = $DomainDNSName
            Credential = $DomainCredentials
            DependsOn  = "[xWaitForADDomain]DscDomainWait"
        } 
    }
}

# Generating MOF File
CAJoinDomain -OutputPath 'C:\CWE\CAJoinDomain' -LocalCredentials $LocalCredentials -DomainCredentials $DomainCredentials -ConfigurationData $ConfigurationData