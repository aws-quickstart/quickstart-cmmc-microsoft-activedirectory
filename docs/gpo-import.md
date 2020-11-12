# DISA STIG GPO Import Process

The Active Directory stack has been extended to include a process for importing DISA STIG GPO (Group Policy Object) backups into Active Directory. 

DISA provides a ZIP file on their [website](https://public.cyber.mil/stigs/gpo/) which contains ADMX template files, GPO backup exports, GPO reports, and WMI filter exports and STIG Checklist files. These are released at the end of each quarter. 

There are two parts to the GPO import process that has been implemented here:

1. Check for new STIG GPO packages on the website and publish notifications
2. Import the GPO backups from the DISA STIG GPO package

## Check for New STIG GPO Packages

This solution includes an AWS Lambda function that runs on the first day of the month following the end of a quarter (January, April, July, October). This function relies of the following in order to work correctly:

- The file naming scheme for the GPO packages on the DISA website will alwas be

    ```
    U_STIG_GPO_Package_LongMonthName_Year.zip
    ```

    For example, the package provided at the end of Q3 2020 is named

    ```
    U_STIG_GPO_Package_October_2020.zip
    ```

- The URL to the GPO package will always stay the same. That URL is
  
  ```
  https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_LongMonthName_Year.zip
  ```

- The folder structure within the ZIP file will always be consistent
- There will always be a manifest.xml file in the GPOs folder for the given operating system and the schema and information for that manifest file will not change

The most recently imported package is stored as a value in the AWS Systems Manager (SSM) Parameter Store as part of the import process. This Lambda function reads that value and determines what the filename of the next package should be. It then attempts to make a request for that file using the HEAD HTTP verb which will return a response code based on whether or not the file exists without actually downloading the file. 

An SNS topic is created as part of the Active Directory stack which is used to push notifications about GPO packages. If the Lambda function finds a new GPO package, it will push a message that a new package is available to the SNS topic. If by the 7th day of the month following the end of a quarter a new GPO package was not found, a message stating such is published to the SNS topic. This SNS topic can be used to send email, create JIRA tickets or push other types of notifications.

## Package Import Process

To import a new GPO package, a user must first download the package from the DISA STIG website. Once they have downloaded the ZIP file, they must upload it to the root of the GPO S3 bucket that was created as part of the Active Directory Stack. It is important that the file name and contents are not modified in any way prior to uploading the package to the S3 bucket.

Uploading the file to S3 will trigger a Lambda function. This function will parse the values for the package and the S3 bucket and pass them as parameters to an AWS Systems Manager Run Command Document. It will also update the values in the SSM Parameter store that identify the most recent package that was processed.

The SSM Run Command Document executes the process of downloading the zip file on the primary domain controller, extracting the package and importing the correct GPO backups into Active Directory. This is done using Powershell scripts. The GPO backups are imported at the domain level so they can be assigned as necessary by the domain adminsitrators.
