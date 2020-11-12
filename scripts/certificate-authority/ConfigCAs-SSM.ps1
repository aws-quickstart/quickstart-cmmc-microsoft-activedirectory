[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)]
    [string]$CRLS3BucketName,
    
    [Parameter(Mandatory = $true)]
    [string]$CRLS3BucketUrl,
    
    [Parameter(Mandatory = $true)]
    [string]$RootCANetBIOSName,
    
    [Parameter(Mandatory = $true)]
    [string]$SubordinateCANetBIOSName,

    [Parameter(Mandatory = $true)]
    [string]$CAAdminSecret,
    
    [Parameter(Mandatory = $true)]
    [string]$DomainAdminSecret,
    
    [Parameter(Mandatory = $true)]
    [string]$DomainDNSName,
    
    [Parameter(Mandatory = $true)]
    [string]$DomainNetBIOSName,

    [Parameter(Mandatory = $true)]
    [string]$Region,

    [string]$CRLOverlapPeriodUnits = '12',
    
    [string]$CRLOverlapPeriod = "Hours",
    
    [string]$ValidityPeriodUnits = '5',
    
    [string]$ValidityPeriod = "Years",

    [string]$AuditFilter = '127'
)

# Get the FIPS endpoint URL
$EndpointUrl = "https://secretsmanager-fips." + $Region + ".amazonaws.com"
# Getting Password from Secrets Manager for CA Admin User
$CAAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -EndpointUrl $EndpointUrl -SecretId $CAAdminSecret).SecretString
# Creating Credential Object for CA Administrator
$CACredentials = (New-Object PSCredential($CAAdminPassword.UserName, (ConvertTo-SecureString $CAAdminPassword.Password -AsPlainText -Force)))
# Getting Password from Secrets Manager for Domain Admin User
$ADAdminPassword = ConvertFrom-Json -InputObject (Get-SECSecretValue -EndpointUrl $EndpointUrl -SecretId $DomainAdminSecret).SecretString
# Formatting Domain Admin User to proper format
$DomainAdmin = 'Domain\User' -replace 'Domain', $DomainNetBIOSName -replace 'User', $ADAdminPassword.UserName
# Creating Credential Object for Domain Administrator
$DomainAdminCredentials = (New-Object PSCredential($DomainAdmin, (ConvertTo-SecureString $ADAdminPassword.Password -AsPlainText -Force)))
# Getting the DSC Cert Encryption Thumbprint for both admins to Secure the MOF File
$RootCADscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | Where-Object { $_.subject -eq "CN=$($RootCANetBIOSName)-DscEncryptCert" }).Thumbprint
$SubCADscCertThumbprint = (get-childitem -path cert:\LocalMachine\My | Where-Object { $_.subject -eq "CN=$($SubordinateCANetBIOSName)-DscEncryptCert" }).Thumbprint
# Convert the bucket URL from HTTPS to HTTP since CRL distribution points do not support HTTPS
$CRLS3BucketUrlHttp = $CRLS3BucketUrl -replace "https", "http"

# Creating Configuration Data Block that has the Certificate Information for DSC Configuration Processing
$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName             = "*"
            PSDscAllowDomainUser = $true
        },
        @{
            # Configuration specific to the Root CA
            NodeName        = $RootCANetBIOSName
            Thumbprint      = $RootCADscCertThumbprint
            CertificateFile = "C:\CWE\publickeys\$($RootCANetBIOSName)-DscPublicKey.cer"
            CACommonName    = $DomainDNSName + " Root CA"
        },
        @{
            # Configuration specific to the Subordinate CA
            NodeName         = $SubordinateCANetBIOSName
            Thumbprint       = $SubCADscCertThumbprint
            CertificateFile  = "C:\CWE\publickeys\$($SubordinateCANetBIOSName)-DscPublicKey.cer"
            CACommonName     = $DomainDNSName + " Issuing CA"
            RootCAName       = $RootCANetBIOSName
            RootCACommonName = $DomainDNSName + " Root CA"
        }
    )
}

Configuration ConfigCAs {
    # Credential Objects being passed in
    param
    (
        [PSCredential] $CACredentials,
        [PSCredential] $DomainAdminCredentials
    )
    
    # Importing DSC Modules needed for Configuration
    Import-Module -Name NetworkingDsc
    Import-Module -Name xActiveDirectory
    Import-Module -Name ActiveDirectoryCSDsc
    Import-Module -Name ComputerManagementDsc
    Import-Module -Name xDnsServer
    Import-Module -Name xPSDesiredStateConfiguration
    
    # Importing All DSC Resources needed for Configuration
    Import-DscResource -ModuleName 'NetworkingDsc'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'ActiveDirectoryCSDsc'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'xDnsServer'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
  
    <# 
        Configuration for the Root CA
    #>
    Node $RootCANetBIOSName {  
        <# 
            Create the CAPolicy.inf file which defines basic properties about the ROOT CA certificate
        #>
        File CAPolicy {
            Ensure          = 'Present'
            DestinationPath = 'C:\Windows\CAPolicy.inf'
            Contents        = "[Version]`r`nSignature=`"$Windows NT$`"`r`n[Certsrv_Server]`r`nRenewalKeyLength=2048`r`nRenewalValidityPeriod=Years`r`nRenewalValidityPeriodUnits=20`r`nCRLPeriod=Weeks`r`nCRLPeriodUnits=26`r`nCRLDeltaPeriod=Days`r`nCRLDeltaPeriodUnits=0`r`nAlternateSignatureAlgorithm=0`r`n[CRLDistributionPoint]`r`n[AuthorityInformationAccess]"
            Type            = 'File'
        } 

        <# 
            Install the ADCS Certification Authority Windows Feature
        #>
        WindowsFeature ADCS-Cert-Authority { 
            Ensure = 'Present' 
            Name   = 'ADCS-Cert-Authority'
        }
               
        <# 
            Configure the ADCS Certification Authority
        #>
        ADCSCertificationAuthority ADCS { 
            Ensure              = 'Present'
            IsSingleInstance    = 'Yes' 
            Credential          = $CACredentials
            CAType              = 'StandaloneRootCA' 
            CACommonName        = $Node.CACommonName
            ValidityPeriod      = 'Years'
            ValidityPeriodUnits = 20
            CryptoProviderName  = 'RSA#Microsoft Software Key Storage Provider'
            HashAlgorithmName   = 'SHA256'
            KeyLength           = 4096
            DependsOn           = '[File]CAPolicy', '[WindowsFeature]ADCS-Cert-Authority'              
        }

        <# 
            Install the ADCS Web Enrollment Windows Feature
        #>
        WindowsFeature ADCS-Web-Enrollment { 
            Ensure     = 'Present' 
            Name       = 'ADCS-Web-Enrollment' 
            Credential = $CACredentials
            DependsOn  = '[WindowsFeature]ADCS-Cert-Authority' 
        }

        <# 
            Install the Remote Server Administration Tools for ADCS Windows Feature
        #>
        WindowsFeature RSAT-ADCS { 
            Ensure    = 'Present' 
            Name      = 'RSAT-ADCS' 
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority' 
        } 
        
        <# 
            Install the Remote Server Administration Tools for ADCS Management Windows Feature
        #>
        WindowsFeature RSAT-ADCS-Mgmt { 
            Ensure    = 'Present' 
            Name      = 'RSAT-ADCS-Mgmt' 
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority' 
        } 
        
        <# 
            Configure the ADCS Web Enrollment
        #>
        ADCSWebEnrollment CertSrv { 
            Ensure           = 'Present' 
            IsSingleInstance = 'Yes'
            Credential       = $CACredentials
            DependsOn        = '[WindowsFeature]ADCS-Web-Enrollment', '[ADCSCertificationAuthority]ADCS'
        } 

        <# 
            Configure the CRL and AIA for the Root CA and upload the certificates to S3
        #>
        Script ADCSAdvConfig {
            SetScript  = {
                # Remove all CRL Distribution Points except for the one located in C:\Windows\system32\CertSrv\CertEnroll
                Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CACRLDistributionPoint -Force
                # Remove all Authority Information Access except for the one located in C:\Windows\system32\CertSrv\CertEnroll
                Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
                # Add a new CRL Distribution Point located in the CRL S3 bucket
                Add-CACRLDistributionPoint -Uri "$($Using:CRLS3BucketUrlHttp)/Root/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -Force 
                # Add a new Authority Information Access located in the CRL S3 bucket
                Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri "$($Using:CRLS3BucketUrlHttp)/Root/<ServerDNSName>_<CaName><CertificateName>.crt" -Force
                #The following commands will set additional configurations to the CA and restart the CA service
                & certutil.exe -setreg CA\CRLOverlapPeriodUnits $($Using:CRLOverlapPeriodUnits)
                & certutil.exe -setreg CA\CRLOverlapPeriod $($Using:CRLOverlapPeriod)
                & certutil.exe -setreg CA\ValidityPeriodUnits $($Using:ValidityPeriodUnits)
                & certutil.exe -setreg CA\ValidityPeriod $($Using:ValidityPeriod)
                & certutil.exe -setreg CA\AuditFilter $($Using:AuditFilter)
                & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable  

                Restart-Service -Name 'certsvc'
                
                # Need to give the certsvc enough time to restart before generating the CRL
                Start-Sleep -s 15

                # The following commands will publish the Certificate Revocation List and create a folder name PKI on the C: drive. 
                # It will then copy the root CA certificate and CRL to the C:\PKI folder. 
                & certutil.exe -crl

                $pkiDir = 'C:\Pki'
                if (!(Test-Path -Path $pkiDir)) {
                    New-Item -Path $pkiDir -Type 'Directory'
                }
                
                Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'C:\Pki\'

                # Upload each of the files to the S3 bucket
                $files = Get-ChildItem "C:\Pki\"
                foreach ($f in $files) {
                    $fileKey = '/Root/' + $f
                    $filePath = 'C:\Pki\' + $f.Name
                    Write-S3Object -BucketName $($Using:CRLS3BucketName) -File $filePath -Key $fileKey -Endpoint "https://s3-fips.$($Using:Region).amazonaws.com" -Region $($Using:Region)
                }
            }
            GetScript  = {
                return @{
                    'CRLPublicationURLs'    = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs');
                    'CACertPublicationURLs' = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs')
                    'CRLOverlapPeriodUnits' = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriodUnits')
                    'CRLOverlapPeriod'      = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriod')
                    'ValidityPeriodUnits'   = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriodUnits')
                    'ValidityPeriod'        = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriod')
                    'AuditFilter'           = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('AuditFilter')
                }
            }
            TestScript = {
                # The following commands validate that the CRL and AIA has been configured correctly
                if ((Get-CACRLDistributionPoint | Where-Object { $_.Uri -eq "$($Using:CRLS3BucketUrlHttp)/Root/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" }).Length -le 0) {
                    return $false
                }                
                if ((Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -eq "$($Using:CRLS3BucketUrlHttp)/Root/<ServerDNSName>_<CaName><CertificateName>.crt" }).Length -le 0) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriodUnits') -ne $($Using:CRLOverlapPeriodUnits)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriod') -ne $($Using:CRLOverlapPeriod)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriodUnits') -ne $($Using:ValidityPeriodUnits)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriod') -ne $($Using:ValidityPeriod)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('AuditFilter') -ne $($Using:AuditFilter)) {
                    return $false
                }
                if (-not (auditpol.exe /get /subcategory:'Certification Services')) {
                    return $false
                }
                if ((Get-Service 'certsvc').Status -ne "Running") {
                    return $false
                }
                if ((Get-ChildItem "C:\Pki\").Count -eq 0) {
                    return $false
                }

                return $true
            }
            DependsOn  = '[ADCSWebEnrollment]CertSrv'
        }

        <# 
            Wait for SubCA to generate REQ and set the MIME type
        #>
        WaitForAny WaitForSubCA {
            ResourceName     = '[Script]SetREQMimeType'
            NodeName         = $SubordinateCANetBIOSName
            RetryIntervalSec = 30
            RetryCount       = 30
            DependsOn        = '[Script]ADCSAdvConfig'
        }
 
        <# 
            Download the REQ from the SubCA
            This file is needed to issue the certificate in the [Script]IssueCert step 
        #>
        xRemoteFile DownloadSubCA {
            DestinationPath = "C:\Windows\System32\CertSrv\CertEnroll\$SubordinateCANetBIOSName.req"
            Uri             = "http://$SubordinateCANetBIOSName/CertEnroll/$SubordinateCANetBIOSName.req"
            DependsOn       = "[WaitForAny]WaitForSubCA"
        }

        <#
            Generate the Issuing Certificate (CRT) from the REQ
            The REQ file is downloaded in the [xRemoteFile]DownloadSubCA step
        #>
        Script IssueCert {
            SetScript  = {                
                Write-Verbose "Submitting C:\Windows\System32\CertSrv\CertEnroll\$($Using:SubordinateCANetBIOSName).req to $($Using:Node.CACommonName)"
                # Submit the request using the REQ file downloaded in the previous step
                [String]$RequestResult = Certreq.exe -Config ".\$($Using:Node.CACommonName)" -Submit "C:\Windows\System32\CertSrv\CertEnroll\$($Using:SubordinateCANetBIOSName).req"
                # Get the Request IDs from the result
                $ResultMatches = [Regex]::Match($RequestResult, 'RequestId:\s([0-9]*)')
                # Validate that the request result contains at least 2 groups as expected
                If ($ResultMatches.Groups.Count -lt 2) {
                    Write-Verbose "Error getting Request ID from SubCA certificate submission."
                    Throw "Error getting Request ID from SubCA certificate submission."
                }
                # Get the Request ID from the second group
                [int]$RequestId = $ResultMatches.Groups[1].Value

                Write-Verbose "Issuing $RequestId in $($Using:Node.CACommonName)"
                # Resubmit the request with the request ID
                [String]$SubmitResult = CertUtil.exe -Resubmit $RequestId
                If ($SubmitResult -notlike 'Certificate issued.*') {
                    Write-Verbose "Unexpected result issuing SubCA request."
                    Throw "Unexpected result issuing SubCA request."
                }

                Write-Verbose "Retrieving C:\Windows\System32\CertSrv\CertEnroll\$($Using:SubordinateCANetBIOSName).req from $($Using:Node.CACommonName)"
                # Generate the CRT file by retrieving the response to the certificate request
                Certreq.exe -Config ".\$($Using:Node.CACommonName)" -Retrieve $RequestId "C:\Windows\System32\CertSrv\CertEnroll\$($Using:SubordinateCANetBIOSName).crt"
            }
            GetScript  = {
                Return @{
                    'Generated' = (Test-Path -Path "C:\Windows\System32\CertSrv\CertEnroll\$($Using:SubordinateCANetBIOSName).crt");
                }
            }
            TestScript = { 
                If (-not (Test-Path -Path "C:\Windows\System32\CertSrv\CertEnroll\$($Using:SubordinateCANetBIOSName).crt")) {
                    # SubCA Cert is not yet created
                    Return $False
                }
                # SubCA Cert has been created
                Return $True
            }
            DependsOn  = "[xRemoteFile]DownloadSubCA"
        }

        <# 
            Wait for SubCA to install the CA Certificate
        #>
        WaitForAny WaitForComplete {
            ResourceName     = '[Script]RegisterSubCA'
            NodeName         = $SubordinateCANetBIOSName
            RetryIntervalSec = 30
            RetryCount       = 30
            DependsOn        = "[Script]IssueCert"
        }
 
        <# 
            Shutdown the Root CA - it is no longer needed because it has issued all SubCAs
        #>
        Script ShutdownRootCA {
            SetScript  = {
                Stop-Computer
            }
            GetScript  = {
                Return @{
                }
            }
            TestScript = { 
                # SubCA Cert is not yet created
                Return $False
            }
            DependsOn  = "[WaitForAny]WaitForComplete"
        }
    }

    <#
        Configuration for the Subordinate CA
    #>
    Node $SubordinateCANetBIOSName {

        # Install the ADCS Certification Authority Windows Feature
        WindowsFeature ADCS-Cert-Authority { 
            Ensure = 'Present' 
            Name   = 'ADCS-Cert-Authority'
        }        

        # Install the ADCS Web Enrollment Windows Feature
        WindowsFeature ADCS-Web-Enrollment { 
            Ensure     = 'Present' 
            Name       = 'ADCS-Web-Enrollment' 
            Credential = $CACredentials
            DependsOn  = '[WindowsFeature]ADCS-Cert-Authority' 
        }

        # Install the Remote Server Adminstration Tools for Active Directory Windows Feature
        WindowsFeature RSAT-AD-Tools {
            Name      = 'RSAT-AD-Tools'
            Ensure    = 'Present'
            DependsOn = "[WindowsFeature]ADCS-Web-Enrollment"
        }

        # Install the Online Responder Service Windows Feature
        WindowsFeature OnlineResponderCA {
            Name      = 'ADCS-Online-Cert'
            Ensure    = 'Present'
            DependsOn = "[WindowsFeature]ADCS-Web-Enrollment"
        }

        # Install the Remote Server Adminstration Tools for ADCS Windows Feature
        WindowsFeature RSAT-ADCS { 
            Ensure    = 'Present' 
            Name      = 'RSAT-ADCS' 
            DependsOn = "[WindowsFeature]RSAT-AD-Tools"
        }         

        # Install the Remote Server Adminstration Tools for ADCS Management Windows Feature
        WindowsFeature RSAT-ADCS-Mgmt { 
            Ensure    = 'Present' 
            Name      = 'RSAT-ADCS-Mgmt' 
            DependsOn = '[WindowsFeature]RSAT-ADCS' 
        } 

        # Create the CAPolicy.inf file which defines basic properties about the Subordinate CA certificate
        File CAPolicy {
            Ensure          = 'Present'
            DestinationPath = 'C:\Windows\CAPolicy.inf'
            Contents        = "[Version]`r`nSignature=`"$Windows NT$`"`r`n[PolicyStatementExtension]`r`nPolicies=InternalPolicy`r`n[InternalPolicy]`r`nOID= 1.2.3.4.1455.67.89.5`r`nNotice=`"Legal Policy Statement`"`r`nURL=" + $CRLS3BucketUrl + "/Subordinate/cps.txt`r`n[Certsrv_Server]`r`nRenewalKeyLength=2048`r`nRenewalValidityPeriod=Years`r`nRenewalValidityPeriodUnits=5`r`nCRLPeriod=Weeks`r`nCRLPeriodUnits=1`r`nCRLDeltaPeriod=Days`r`nCRLDeltaPeriodUnits=0`r`nLoadDefaultTemplates=0`r`nAlternateSignatureAlgorithm=0`r`n"
            Type            = 'File'
        }   
        
        <#
            Make a CertEnroll folder to put the Root CA certificate into
            The CA Web Enrollment server would also create this but we need it now
        #>
        File CertEnrollFolder {
            Ensure          = 'Present'
            DestinationPath = 'C:\Windows\System32\CertSrv\CertEnroll'
            Type            = 'Directory'
            DependsOn       = '[File]CAPolicy'
        }

        # Wait for the Root CA to generate and upload the certificate and CRL files
        WaitForAny RootCA {
            ResourceName     = '[Script]ADCSAdvConfig'
            NodeName         = $RootCANetBIOSName
            RetryIntervalSec = 30
            RetryCount       = 30
            DependsOn        = "[File]CertEnrollFolder"
        }
 
        # Download the Root CA CRT file from S3
        Script DownloadRootCACRTFile {
            SetScript  = {
                Read-S3Object -BucketName $($Using:CRLS3BucketName) -Key "Root/$($Using:Node.RootCAName).$($Using:DomainDNSName)_$($Using:Node.RootCACommonName).crt" -File "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName).$($Using:DomainDNSName)_$($Using:Node.RootCACommonName).crt" -Endpoint "https://s3-fips.$($Using:Region).amazonaws.com" -Region $($Using:Region)
            }
            GetScript  = {
                Return @{
                }
            }
            TestScript = { 
                If (-not (Test-Path "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName).$($Using:DomainDNSName)_$($Using:Node.RootCACommonName).crt")) {
                    Write-Verbose "RootCA CRT file failed to download from S3"
                    Return $false
                }
                Return $true
            }
            DependsOn  = '[WaitForAny]RootCA'
        }
 
        
        # Download the Root CA CRL file from S3
        Script DownloadRootCACRLFile {
            SetScript  = {
                Read-S3Object -BucketName $($Using:CRLS3BucketName) -Key "Root/$($Using:Node.RootCACommonName).crl" -File "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCACommonName).crl" -Endpoint "https://s3-fips.$($Using:Region).amazonaws.com" -Region $($Using:Region)
            }
            GetScript  = {
                Return @{
                }
            }
            TestScript = { 
                If (-not (Test-Path "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCACommonName).crl")) {
                    Write-Verbose "RootCA CRL file failed to download from S3"
                    Return $false
                }
                Return $true
            }
            DependsOn  = '[Script]DownloadRootCACRTFile'
        }

        # Install the Root CA Certificate and CRL to the LocalMachine Root Store and Active Directory
        Script InstallRootCACert {
            PSDSCRunAsCredential = $DomainAdminCredentials
            SetScript            = {
                Write-Verbose "Registering the Root CA Certificate C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName).$($Using:DomainDNSName)_$($Using:Node.RootCACommonName).crt in DS..."
                # Publish the Root CA certificate to Active Directory
                & "$($ENV:SystemRoot)\system32\certutil.exe" -f -dspublish "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName).$($Using:DomainDNSName)_$($Using:Node.RootCACommonName).crt" RootCA
                
                Write-Verbose "Registering the Root CA CRL C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCACommonName).crl in DS..."
                # Publish the Root CA CRL to Active Directory
                & "$($ENV:SystemRoot)\system32\certutil.exe" -f -dspublish "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCACommonName).crl" RootCA    
                
                Write-Verbose "Installing the Root CA Certificate C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName).$($Using:DomainDNSName)_$($Using:Node.RootCACommonName).crt..."
                # Add the Root CA certificate to the root certificate store
                & "$($ENV:SystemRoot)\system32\certutil.exe" -addstore -f root "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName).$($Using:DomainDNSName)_$($Using:Node.RootCACommonName).crt"
                
                Write-Verbose "Installing the Root CA CRL C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCACommonName).crl..."
                # Add the Root CA CRL to the root certificate store
                & "$($ENV:SystemRoot)\system32\certutil.exe" -addstore -f root "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCACommonName).crl"
            }
            GetScript            = {
                Return @{
                    Installed = ((Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object -FilterScript { ($_.Subject -eq "CN=$($Using:Node.RootCACommonName)") -and ($_.Issuer -eq "CN=$($Using:Node.RootCACommonName)") } ).Count -EQ 0)
                }
            }
            TestScript           = { 
                # Check if the certificate has already been installed
                If ((Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object -FilterScript { ($_.Subject -eq "CN=$($Using:Node.RootCACommonName)") -and ($_.Issuer -eq "CN=$($Using:Node.RootCACommonName)") } ).Count -EQ 0) {
                    Write-Verbose "Root CA Certificate Needs to be installed..."
                    Return $False
                }
                Return $True
            }
            DependsOn            = '[Script]DownloadRootCACRLFile'
        }

        <#
            Configure the Sub CA which will create the Certificate REQ file that Root CA will use
            to issue a certificate for this Sub CA.
        #>
        ADCSCertificationAuthority ConfigCA {
            Ensure                  = 'Present'
            IsSingleInstance        = 'Yes'
            Credential              = $DomainAdminCredentials
            CAType                  = 'EnterpriseSubordinateCA'
            CACommonName            = $Node.CACommonName
            OverwriteExistingCAinDS = $true
            OutputCertRequestFile   = "c:\Windows\System32\CertSrv\CertEnroll\$SubordinateCANetBIOSName.req"
            CryptoProviderName      = 'RSA#Microsoft Software Key Storage Provider'
            HashAlgorithmName       = 'SHA256'
            KeyLength               = 2048
            DependsOn               = '[Script]InstallRootCACert'
        }

        # Configure the Web Enrollment Feature
        ADCSWebEnrollment ConfigWebEnrollment {
            Ensure           = 'Present'
            IsSingleInstance = 'Yes'
            Credential       = $DomainAdminCredentials
            DependsOn        = '[ADCSCertificationAuthority]ConfigCA'
        }

        # Set the IIS Mime Type to allow the REQ request to be downloaded by the Root CA
        Script SetREQMimeType {
            SetScript  = {
                Add-WebConfigurationProperty -PSPath IIS:\ -Filter //staticContent -Name "." -Value @{fileExtension = '.req'; mimeType = 'application/pkcs10' }
            }
            GetScript  = {
                Return @{
                    'MimeType' = ((Get-WebConfigurationProperty -Filter "//staticContent/mimeMap[@fileExtension='.req']" -PSPath IIS:\ -Name *).mimeType);
                }
            }
            TestScript = { 
                If (-not (Get-WebConfigurationProperty -Filter "//staticContent/mimeMap[@fileExtension='.req']" -PSPath IIS:\ -Name *)) {
                    # Mime type is not set
                    Return $False
                }
                # Mime Type is already set
                Return $True
            }
            DependsOn  = '[ADCSWebEnrollment]ConfigWebEnrollment'
        }

        # Wait for the Root CA to have completed issuance of the certificate for this Sub CA
        WaitForAny SubCACer {
            ResourceName     = "[Script]IssueCert"
            NodeName         = $RootCANetBIOSName
            RetryIntervalSec = 30
            RetryCount       = 30
            DependsOn        = "[Script]SetREQMimeType"
        }
 
        # Download the Certificate for this Sub CA from S3
        xRemoteFile DownloadSubCACERFile {
            DestinationPath = "C:\Windows\System32\CertSrv\CertEnroll\$($Node.NodeName)_$($Node.CACommonName).crt"
            Uri             = "http://$RootCANetBIOSName/CertEnroll/$SubordinateCANetBIOSName.crt"
            DependsOn       = '[WaitForAny]SubCACer'
        }

        # Register the Sub CA Certificate with the Certification Authority
        Script RegisterSubCA {
            # Run as the Domain Admin
            PSDSCRunAsCredential = $DomainAdminCredentials
            SetScript            = {
                Write-Verbose "Registering the Sub CA Certificate with the Certification Authority C:\Windows\System32\CertSrv\CertEnroll\$($Node.NodeName)_$($Node.CACommonName).crt..."
                # Install the certificate for the Sub CA
                certutil.exe -installCert "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.NodeName)_$($Using:Node.CACommonName).crt"
            }
            GetScript            = {
                Return @{
                }
            }
            TestScript           = { 
                If (-not (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertHash')) {
                    Write-Verbose "Sub CA Certificate needs to be registered with the Certification Authority..."
                    Return $False
                }
                Return $True
            }
            DependsOn            = '[xRemoteFile]DownloadSubCACERFile'
        }

        <# 
            Configure the CRL and AIA for the Sub CA and upload the certificates to S3
            The Certsvc service will be restarted after completing the CRL and AIA configuration
        #>
        Script ADCSAdvConfig {
            SetScript  = {
                # Remove all CRL Distribution Points except for the one located in C:\Windows\system32\CertSrv\CertEnroll
                Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CACRLDistributionPoint -Force
                # Remove all Authority Information Access except for the one located in C:\Windows\system32\CertSrv\CertEnroll
                Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force
                # Add a new CRL Distribution Point located in the S3 bucket
                Add-CACRLDistributionPoint -Uri "$($Using:CRLS3BucketUrlHttp)/Subordinate/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -Force 
                # Add a new Authority Information Access located in the S3 bucket defined in Step 2: Setup S3 Bucket to Store Certificate Revocation Lists (CRLs) and Certificates
                Add-CAAuthorityInformationAccess -AddToCertificateAia -Uri "$($Using:CRLS3BucketUrlHttp)/Subordinate/<ServerDNSName>_<CaName><CertificateName>.crt" -Force
                # Set additional configurations to the CA and restart the CA service
                & certutil.exe -setreg CA\CRLOverlapPeriodUnits $($Using:CRLOverlapPeriodUnits)
                & certutil.exe -setreg CA\CRLOverlapPeriod $($Using:CRLOverlapPeriod)
                & certutil.exe -setreg CA\ValidityPeriodUnits $($Using:ValidityPeriodUnits)
                & certutil.exe -setreg CA\ValidityPeriod $($Using:ValidityPeriod)
                & certutil.exe -setreg CA\AuditFilter $($Using:AuditFilter)
                & auditpol.exe /set /subcategory:'Certification Services' /failure:enable /success:enable  

                Restart-Service -Name 'certsvc'   

                # Need to give the certsvc enough time to restart before generating the CRL
                Start-Sleep -s 15

                # Publish the Certificate Revocation List and create a folder name PKI on the C: drive
                & certutil.exe -crl
                
                $pkiDir = 'C:\Pki'
                if (!(Test-Path -Path $pkiDir)) {
                    New-Item -Path $pkiDir -Type 'Directory'
                }
                # Then copy the root CA certificate and CRL to the C:\PKI folder
                Copy-Item -Path 'C:\Windows\System32\CertSrv\CertEnroll\*.cr*' -Destination 'C:\Pki\' 
                
                # Upload each of the files to the S3 bucket
                $files = Get-ChildItem "C:\Pki\"
                foreach ($f in $files) {
                    $fileKey = '/Subordinate/' + $f
                    $filePath = 'C:\Pki\' + $f.Name
                    Write-S3Object -BucketName $($Using:CRLS3BucketName) -File $filePath -Key $fileKey -Endpoint "https://s3-fips.$($Using:Region).amazonaws.com" -Region $($Using:Region)
                }
            }
            GetScript  = {
                return @{
                    'DSConfigDN'            = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSConfigDN');
                    'DSDomainDN'            = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSDomainDN');
                    'CRLPublicationURLs'    = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs');
                    'CACertPublicationURLs' = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs')
                }
            }
            TestScript = {
                # The following commands validate that the CRL and AIA has been configured correctly
                if ((Get-CACRLDistributionPoint | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' }).Uri -ne "$($Using:CRLS3BucketUrlHttp)/Subordinate/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl") {
                    return $false
                }
                if ((Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' }).Uri -ne "$($Using:CRLS3BucketUrlHttp)/Subordinate/<ServerDNSName>_<CaName><CertificateName>.crt") {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriodUnits') -ne $($Using:CRLOverlapPeriodUnits)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriod') -ne $($Using:CRLOverlapPeriod)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriodUnits') -ne $($Using:ValidityPeriodUnits)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriod') -ne $($Using:ValidityPeriod)) {
                    return $false
                }
                if ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('AuditFilter') -ne $($Using:AuditFilter)) {
                    return $false
                }
                if (-not (auditpol.exe /get /subcategory:'Certification Services')) {
                    return $false
                }
                if ((Get-Service 'certsvc').Status -ne "Running") {
                    return $false
                }
                if ((Get-ChildItem "C:\Pki\").Count -eq 0) {
                    return $false
                }

                return $true
            }
            DependsOn  = '[Script]RegisterSubCA'
        }

        # Configure the Auto Enroll with LDAPS feature for the CA
        Script ConfigureAutoEnroll {
            # This script must be run with the Domain Admin credentials
            PSDSCRunAsCredential = $DomainAdminCredentials
            SetScript            = {
                New-ADCSTemplate -DisplayName "LDAPOverSSL" -JSON (Export-ADCSTemplate -DisplayName "Kerberos Authentication") -Identity "$($Using:DomainDNSName)\Domain Controllers" -AutoEnroll -Publish
            }
            GetScript            = {
                Return @{
                }
            }
            TestScript           = {
                If (-not (Get-ADCSTemplate -DisplayName "LDAPOverSSL")) {
                    Return $False
                }
                Return $True
            }
            DependsOn            = '[Script]ADCSAdvConfig'
        }

        # Configure HTTPS for web enroll
        Script ConfigureWebEnrollHttps {
            # This script must be run with the Domain Admin credentials
            PSDSCRunAsCredential = $DomainAdminCredentials
            SetScript            = {
                # Create a certificate template to use for generating the SSL certificate
                New-ADCSTemplate -DisplayName SSLCerts -JSON (Export-ADCSTemplate -DisplayName "Web Server") -Publish
                # Wait for the certificate to be available on the domain
                Start-Sleep -s 15
                # Generate a certificate using the template
                Get-Certificate -Template SSLCerts -DnsName "$($Using:Node.NodeName).$($Using:DomainDNSName)" -SubjectName "CN=$($Using:Node.NodeName)-SSL" -CertStoreLocation "Cert:\LocalMachine\My"
                # Get the thumbprint from the generated certificate
                $thumb = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object -FilterScript { ($_.Subject -eq "CN=$($Using:Node.NodeName)-SSL") } )[0].Thumbprint
                # Add the HTTPS binding to IIS using the new certificate
                New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:443:" -CertificateThumbPrint $thumb -CertStoreLocation "Cert:\LocalMachine\My" -Protocol https -Force
            }
            GetScript            = {
                Return @{
                }
            }
            TestScript           = {
                If (-not (Get-IISSiteBinding "Default Web Site" -Protocol "https")) {
                    Return $False
                }
                Return $True
            }
            DependsOn            = '[Script]ConfigureAutoEnroll'
        }
    }
}

# Generating MOF File
ConfigCAs -OutputPath 'C:\CWE\ConfigCAs' -CACredentials $CACredentials -DomainAdminCredentials $DomainAdminCredentials -ConfigurationData $ConfigurationData



