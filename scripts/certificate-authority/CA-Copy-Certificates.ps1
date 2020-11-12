[CmdletBinding()]
# Incoming Parameters for Script, CloudFormation\SSM Parameters being passed in
param(
    [Parameter(Mandatory = $true)]
    [string]$CRLS3BucketName,

    [Parameter(Mandatory = $true)]
    [string]$HostName
)

# Download the certificate for the current host from S3
Read-S3Object -BucketName $CRLS3BucketName -Key "\publickeys\$($HostName)-DscPublicKey.cer" -File "C:\CWE\publickeys\$($HostName)-DscPublicKey.cer" -Endpoint "https://s3-fips.$($Using:Region).amazonaws.com" -Region $($Using:Region)
# Install the certificate to the the local machine certificate store
Import-Certificate -FilePath "C:\CWE\publickeys\$($HostName)-DscPublicKey.cer" -CertStoreLocation Cert:\LocalMachine\My

