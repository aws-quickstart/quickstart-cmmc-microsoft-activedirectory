# CMMC Ready Microsoft Active Directory and Certificate Authority

## Deployment Guide

### Prerequisites

1. Create an S3 bucket to upload the solution files to
2. Upload the following directories and all files within the directories:
    - Archives
    - Scripts
    - Templates
3. Create a Key Pair to use with the EC2 instances
4. If/when changes are made to the index.js file for the GPOPackagesFunction Lambda function, you will need to create a ZIP archive with just that file and name it `GPOPackagesFunction.zip`. You will then need to replace the archive with the same name in the `archives` folder. This will need to be done prior to uploading the file in step 2 above

### Deployment Process

1. Create a new Stack in CloudFormation using the ad-master-1-ssm.template.yaml file in the source files S3 bucket
2. Enter the parameters for your solution. For testing, you can use the defaults with the exception of the following:
    - **Availability Zones**
      - Select 2 availability zones. You can select more but the solution only uses the first 2
    - **Allowed Remote Desktop Gateway External Access CIDR**
    - **Key Pair Name**
      - Select the Key Pair that you created as a prerequisite
    - **Primary Domain Administator Password**
    - **Alternate Domain Administrator Password**
    - **AD Restore Mode Password**
    - Add a suffix to all bucket names
      - This is because all bucket names must be unique. Currently we do not append anything to the bucket names in the solution

The deployment will take between 60-90 mins to complete. 

Part of the Active Directory Stack will run an AWS Systems Manager (SSM) automation document and you can view that progress in the SSM automation console. This is triggered once the DomainController2 is setup. 

The CA stack also runs an SSM automation document once the Subordinate CA instance is setup. Most errors should cause the stack to fail but the stack will not show you the details of the errors in the automation processes. You will have to click through the automation processes to get the details of those. You can also find additional logging in the CloudWatch logs.

### Post-Deployment Steps

1. Once everything is set up, you need to upload the current DISA STIG GPO package to the GPO S3 bucket. For more information on this process, read the [DISA STIG GPO Import Process documentation](docs/gpo-import.md)
2. This will kick off the process that imports the GPO backups into Active Directory. The manual process only needs to be done once after initial deployment
3. Going forward, there is a Lambda function that checks the DISA website for a new package on a defined schedule and sends an SNS notification when a package is found or when it has not been found but should have been available.

## Template Descriptions


### ```ad-main-1-ssm.template.yaml```

The main template that takes all parameter entries, creates the KMS customer-managed key (CMK), and launches the relevant nested stacks.

### ```ad-1-ssm.template.yaml```
Launches the Active Directory infrastructure and installs and configures the domain controllers. This stack also deploys the resources for the DISA STIG GPO Import Process

### ```nested/aws-vpc.template.yaml```

If parameters are not entered for an existing VPC, this template will be launched to set up the VPC architecture.

### ```nested/rdgw-domain.template.yaml```

Deploys a simple Remote Desktop Gateway architecture that will automatically join the deployed Active Directory infrastructure.

### ```nested/ad-ca.yaml```

Deploys a [two-tier Microsoft PKI infrastructure](docs/certification-authority.md) consisting of an offline Root CA and an Enterprise Subordinate CA.

## Aspects of Hardening

To comply with governance and security requirements, this template utilizes:

- KMS CMK for use with EBS and Secrets Manager encryption
- AWS API FIPS endpoints
- Local customer-controlled file download sources
- Implementation of DISA STIGs
