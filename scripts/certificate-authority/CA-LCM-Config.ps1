# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)]
    [string]$HostName
)

# This block sets the LCM configuration to what we need for QS
[DSCLocalConfigurationManager()]

configuration LCMConfig
{
    Node 'localhost' {
        Settings {
            RefreshMode        = 'Push'
            ActionAfterReboot  = 'StopConfiguration'                      
            RebootNodeIfNeeded = $false
            CertificateId      = $DscCertThumbprint
        }
    }
}

# Getting the DSC Cert Encryption Thumbprint to Secure the MOF File based on the host name
$DscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | Where-Object { $_.subject -eq "CN=$($HostName)-DscEncryptCert" }).Thumbprint
    
#Generates MOF File for LCM
LCMConfig -OutputPath 'C:\CWE\LCMConfig'
    
# Sets LCM Configuration to MOF generated in previous command
Set-DscLocalConfigurationManager -Path 'C:\CWE\LCMConfig' -Verbose -Force