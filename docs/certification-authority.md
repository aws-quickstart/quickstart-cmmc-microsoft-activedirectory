# Microsoft Two-Tier PKI Configuration

This solution deploys a two-tier PKI setup consisting of an offline Root Certification Authority (CA) and an Enterprise Subordinate Certification Authority (CA). The CAs are both configured to run on Microsoft Windows Server hosts that are joined to Microsoft Active Directory (AD) and running on Amazon EC2 instances.

An Amazon S3 bucket is setup along with the CA instances. This bucket is used as the Certificate Revocation Lists (CRL) distribution point. It is also used to fasicilate the transfer of certificates between the Root CA and Subordinate CA during the setup process.

The user logins for Active Directory and the CAs are stored in AWS Secrets Manager. There are 4 logins: domain administrator, alternate domain administrator restore credentials for Active Directory and the local administrator for the CA instances.

## Setup Process

The setup for the CAs is an automated process. An AWS System Manager (SSM) automation document is used to execute a series of Powershell and Powershell DSC scripts in a specific order necessary to complete the entire configuration. Parameter and resource values are passed to the SSM document from the CloudFormation Stack. The document executes the following steps in order:

1. The Instance IDs for each of the CA instances is retrieved
2. The required Powershell modules are installed from the PSGallery on each of the CA instances
3. A self-signed certificate is generated on each instance that is used to encrypt/decrypt the Powershell DSC credentials on the given instance
4. The encrpytion certificates are uploaded to the CRL S3 bucket
5. The certificate for the opposing CA is downloaded on each CA instance and imported into the local computer certificate store _(ex. Root CA downloads the certificates for Sub CA)_
    > **Note:** This is necessary because the Powershell DSC script will configure both CA instances at the same time and it will need to decrypt the credentials and use the appropriate certificate given which instance it is configuring at the time.
6. The DSC Local Configuration Manager (LCM) is configured on each instance. The LCM is instantiated with the self-signed encryption certificate for the given instance
7. The MOF files are created on each CA instance with the configuration for renaming the instance to the provided host name, setting the local administrator password and joining the instance to the Active Directory domain
8. The LCM executes the configuration based on those MOFs on each of the CA instances. When complete, the instances are renamed and joined to the domain and then restarted to complete the setup.
    > **Note:** If the instances are not restarted, the renaming of the instance doesn't in fact take effect and therefore the proceeding scripts cannot reference each CA by name
9. The MOF files are created on each instance with the configuration for setting up Active Directory Certificate Services (ADCS) and all other components and functions necessary to complete the CA configuration process
10. The LCM executes the MOF file on the Subordinate CA instance to complete the configuration of both CA instances. This is where the majority of the heavy lifting occurs.
    > **Note:** This is executed from the Subordinate CA only because the last step in the process is to shutdown the Root CA but also because if you execute it on both instances it actually becomes two separate configuration processes and they will collide with each other

The last step in this process where it runs the configuration for both of the CA instances requires a carefully orchestrated set of actions. This is done using a cross-node configuration script in Powershell DSC which allows a given node to wait for a step to complete on another node before proceeding with the configuration.

## Security

All of the user credentials that are provided to the CloudFormation Stack are stored in AWS Secrets Manager. These Powershell scripts create secure credentail objects by access the Secrets via the FIPS endpoint in the given region for Secrets Manager.

The EBS drives for the Root CA and Subordinate CA instances are encrypted using an AWS Key Management Service Customer Managed Key (KMS CMK). This CMK is created in the parent stack and the Key ID is passed to the CA stack via parameters.

The S3 bucket for the CRL files has a policy that only allows access through the S3 VPC Endpoint. That endpoint is either created via the VPC Stack or is provided via parameters.

The EC2 instances are part of the CA Security Group. This security group only allows traffic from the Domain Controllers Security Group and Domain Members Security Group. Both of those security groups are created in the Active Directory Stacks and the IDs are passed into the CA Stack via parameters.

IAM roles are created and assigned to the SSM automation document and the EC2 instances. These roles follow the principle of least-privilege.