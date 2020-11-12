const AWS = require("aws-sdk");
const ssm = new AWS.SSM();
const sns = new AWS.SNS();
const https = require("https");

// global variables
const failureSentName = process.env.FAILURE_SENT_PARAM;
const lastPackageName = process.env.LAST_PKG_PARAM;
const topicArn = process.env.TOPIC_ARN;
const disa = {
  DownloadBaseUrl: "dl.dod.cyber.mil",
  PackagePath: "/wp-content/uploads/stigs/zip/",
  GPOWebsiteUrl: "https://public.cyber.mil/stigs/gpo/",
};
let pkgFileName = "";

exports.handler = async (event) => {
  try {
    await sendGPOPackageNotification();
  } catch (error) {
    console.log(error);
  }
};

// sends an SNS notification about whether or not a new GPO package
// could be found on the DISA website
async function sendGPOPackageNotification() {
  try {
    const failureSent = false; //await wasFailureSent();
    // if a previous failure message was sent, exit out
    // this is to prevent sending multiple failure messages
    if (failureSent) {
      return;
    }

    const currentPkg = await getCurrentPackageSSM();
    const searchDate = await getSearchDate(currentPkg);
    const packageFound = await checkForNewPackage(searchDate);

    // if the current date is on of after the search date, check for a new GPO package
    if (Date.now() >= searchDate) {
      // create SNS notification for when a new package is found
      let snsParams = {
        Message: `A new DISA STIG GPO package is available for download on the DISA website. 
                  It is highly recommended that you download this package and upload it to the S3 bucket so the GPOs just be installed/updated in Active Directory.\n 
                  Link to GPO package: https://${disa.DownloadBaseUrl}${disa.PackagePath}${pkgFileName}.zip\n
                  Link to DISA STIGs: ${disa.GPOWebsiteUrl}`,
        Subject: "New DISA STIG GPO package available for download",
        TopicArn: topicArn,
      };

      if (!packageFound) {
        let alertDate = searchDate;
        alertDate.setDate(7);

        // if a new package was not found and it is at least a week into the month, send a failure notification
        if (Date.now() >= alertDate) {
          // set the SNS message and subject for the failure notification
          snsParams = {
            Message: `A new DISA STIG GPO package was not found on the DISA website but should be available by now. It is highly recommend to go to the 
                    DISA website and see if a package is available or further information about a release date is posted.\n
                    Link to DISA STIGs: ${disa.GPOWebsiteUrl}`,
            Subject:
              "A New DISA STIG GPO package was not found on the DISA website",
            TopicArn: topicArn,
          };

          // update the SSM parameter identifying that a failure message was sent
          await updateFailureSSM("true");
        }
      }

      // publish message to the SNS topic
      await sns.publish(snsParams).promise();
    }
  } catch (error) {
    console.log(error);
  }
}

// gets the value of the most recent GPO package from SSM Parameter Store
async function getCurrentPackageSSM() {
  const ssmPackageParams = {
    Name: lastPackageName,
  };
  const currentPkgParam = await ssm.getParameter(ssmPackageParams).promise();
  return currentPkgParam.Parameter.Value;
}

// determines whether or not a failure message has already been sent
// by checking the value in the SSM Parameter Store
async function wasFailureSent() {
  const ssmFailureParams = {
    Name: failureSentName,
  };
  const failureSentParam = await ssm.getParameter(ssmFailureParams).promise();
  return failureSentParam.Parameter.Value == "true";
}

// updates the SSM Parameter Store value that identies whether or not a
// failure message has been sent
async function updateFailureSSM(failureSent) {
  const ssmFailureParams = {
    Name: failureSentName,
    Value: failureSent,
    Overwrite: true,
  };
  await ssm.putParameter(ssmFailureParams).promise();
}

// gets the date that should be used when searching for a new GPO package
async function getSearchDate(currentPkg) {
  const months = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ];

  // parse the month and year from the file name and convert to a Date object
  const fileNameParts = currentPkg.split("_");
  const month = fileNameParts[4];
  const year = fileNameParts[5];
  const pkgDate = new Date(year, months.indexOf(month));
  // add 4 months to the date because the packages are released in the month following
  // a new quarter but the file name includes the last month of the quarter
  pkgDate.setMonth(pkgDate.getMonth() + 4);
  // set the day to the first of the month
  pkgDate.setDate(1);
  return pkgDate;
}

// checks the DISA website for a new GPO package
async function checkForNewPackage(searchDate) {
  console.log(searchDate);
  // the file date has the month name of the end of the quarter so we need to subtract a monthh
  searchDate.setMonth(searchDate.getMonth() - 1);

  // get the string value of the month from the Date object
  const searchMonth = searchDate.toLocaleString("default", { month: "long" });

  // create the file name to look for using the naming convention of the previous packages from DISA
  pkgFileName = `U_STIG_GPO_Package_${searchMonth}_${searchDate.getFullYear()}`;

  // form the options for making a request for the new package
  var options = {
    method: "HEAD",
    hostname: disa.DownloadBaseUrl,
    protocol: "https:",
    port: 443,
    path: `${disa.PackagePath}${pkgFileName}.zip`,
  };

  let res = await makeRequest(options);

  return res.statusCode == "200";
}

// this function is needed in order to get the response
// from the request before returning the result
function makeRequest(options) {
  return new Promise((resolve, reject) => {
    let req = https.request(options, (res) => {
      resolve(res);
    });

    req.on("data", (res) => {
      resolve(res);
    });

    req.on("error", (err) => {
      reject(err);
    });

    req.end();
  });
}
