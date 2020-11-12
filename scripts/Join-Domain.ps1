[CmdletBinding()]
param(
    [string]
    $DomainName,

    [string]
    $DomainAdminSecret,

    [Parameter(Mandatory = $true)]
    [string]$Region
)

try {
    $ErrorActionPreference = "Stop"

    # Get the fips endpoint URL
    $EndpointUrl = "https://secretsmanager-fips." + $Region + ".amazonaws.com"
    $pass = ConvertFrom-Json -InputObject (Get-SECSecretValue -EndpointUrl $EndpointUrl -SecretId $DomainAdminSecret).SecretString
    $cred = (New-Object System.Management.Automation.PSCredential($pass.UserName, (ConvertTo-SecureString $pass.Password -AsPlainText -Force)))

    Add-Computer -DomainName $DomainName -Credential $cred -ErrorAction Stop

    # Execute restart after script exit and allow time for external services
    $shutdown = Start-Process -FilePath "shutdown.exe" -ArgumentList @("/r", "/t 10") -Wait -NoNewWindow -PassThru
    if ($shutdown.ExitCode -ne 0) {
        throw "[ERROR] shutdown.exe exit code was not 0. It was actually $($shutdown.ExitCode)."
    }
}
catch {
    $_ | Write-AWSQuickStartException
}
