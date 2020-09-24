# McAfee TIE multi-sandbox integration
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This integration allows you to submit files from McAfee Threat Intelligence Exchange (TIE) to multiple sandboxes which allows better threat validation.

TIE by default is able to submit files to McAfee Advanced Threat Defense (ATD) for file analysis only.
McAfee TIE acts as a hash repository with multiple reputation information. As soon an Endpoint executes an unknown file, TIE will automatically receive the file from the endpoint for file analysis and submit this file to ATD.

This integration simulates the McAfee ATD API's, receives the file from McAfee TIE and submits files to various sandboxes for multi sandbox analysis. In this example TIE will submit files to the following sandboxes:
* McAfee ATD
* Lastline
* VMRay

The different sandbox results will update TIE via ATD Reputation and External/Enterprise reputation.

<img width="1126" alt="Screenshot 2019-10-31 at 14 33 00" src="https://user-images.githubusercontent.com/25227268/67951221-614f8b00-fbeb-11e9-8ae8-03c4058a9d49.png">

Adding multiple third party sandboxes results in aggregated reputation levels, with the lowest result being used as overall result. As an example:

1) Sample is sent to 3 sandboxes by TIE
1) Sandbox x finishes first and sets the level in TIE to *MIGHT_BE_TRUSTED*
1) Sandbox y finishes second and would set the level to *MOST_LIKELY_TRUSTED*. Since this is a higher score than the previously determined one, the level in TIE is not changed
1) Sandbox z finishes third and returns a verdict of *MOST_LIKELY_MALICIOUS*. This level has a lower score than the one reported by sandbox x and therefore the level in TIE is changed to it

## Component Description
**McAfee Threat Intelligence Exchange (TIE)** acts as a reputation broker to enable adaptive
threat detection and response. https://www.mcafee.com/enterprise/en-us/products/threat-intelligence-exchange.html

**McAfee Advanced Threat Defense (ATD)** is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides local threat intelligence. ATD exports IOC data in STIX format in several ways including the DXL.
https://www.mcafee.com/in/products/advanced-threat-defense.aspx

**Lastline Analyst** provides threat analysts and incident response teams with the advanced malware inspection and isolation environment they need to safely execute advanced malware samples and understand their behavior. 
https://www.lastline.com/solutions/analyst/

**VMRay Platform** is a virtually undetectable malware analysis platform, providing full visibility into malware’s behavior. This unbeatable combination yields deep insight into advanced threats and complete, precise results, shortening investigation times and increasing the efficiency of SOC and DFIR teams. 
https://www.vmray.com/malware-detection-analysis-platform/

## Configuration

The configuration consists of [one-time setup steps](#one-time-setup) and of the configuration of the [runtime environment](#environment-variables).

### One-time setup

1) Create Web Server Certificates for TLS. e.g.

   ```openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem```

1) Install the dependencies
   1) General: ```pip install -r requirements.txt```
   1) VMRay:
      1) Download the API client from the knowledge center, extract it in the current folder
      1) ```pip install vmray_rest_api-x.y.z.zip```

1) Configure all [environment variables](#environment-variables)

   
1) To submit files from TIE to the multi-sandbox service change the IP, Username and Password (aligned to the TIE username and password configured using the [environment variables](#environment-variables)) in ePO to point to the new created service. **Also make sure that the polling target in the polling settings is set to None!**

   <img width="1440" alt="Screenshot 2019-10-31 at 13 26 12" src="https://user-images.githubusercontent.com/25227268/67946645-0ebda100-fbe2-11e9-9ae3-8b4e33f3c72e.png">

### Environment variables

The script can be configured using environment variables. These can either be set the usual way in the environment itself, or they can be added to the provided .env file. **Make sure to comment out or delete all variables which are not used or going to be set via the environment from the file.**

The available variables are:
| Variable | Target | Description | Default |
|---|---|---|---|
| LOG_LEVEL | General | The log level that will be used. NOTE: This also changes the log level of all involved libraries  | INFO |
| LOG_FILE_PATH| General | The full path to the log file | tie_retriever.log |
|  |  |  |
| TIE_USER | TIE | The username for the TIE server |  |
| TIE_PW | TIE | The password for the TIE server |  |
| TIE_CERTIFICATE_PATH | TIE | The full path to the certificate to be used to secure connections to this script using TLS |  |
| TIE_KEY_PATH | TIE |  The full path to the key to be used to secure connections to this script using TLS |  |
| TIE_FILE_RETRIEVER_PORT | TIE | The port to which this script shall be bound |  |
|  |  |  |
| ATD_ENABLED | ATD | Whether ATD is enabled  | true |
| ATD_IP | ATD | The IP (and port if necessary) of the ATD instance |  |
| ATD_USER | ATD | The ATD username |  |
| ATD_PW | ATD | The ATD password |  |
| ATD_PROFILE | ATD | The VM profile that will be used for the analysis | 1 |
| ATD_TIMEOUT | ATD | Timout value for ATD processing, i.e. after what time the results will be discarded | 600 |
|  |  |  |
| DXL_CONNECTOR_CLIENT_CONFIG_PATH | TIE DXL Connector | The full path to the *dxlclient.config* file |   |
|  |  |  |
| LASTLINE_ENABLE | Lastline | Whether this sandbox is enabled | true |
| LASTLINE_URL | Lastline | The URL of the Lastline Analyst instance | https://user.lastline.com/papi |
| LASTLINE_USER | Lastline | The Lastline username |  |
| LASTLINE_PW | Lastline | The passwort corresponding to the Lastline username |  |
|  |  |  |
| VMRAY_ENABLED | VMRay | Whether this sandbox is enabled | true |
| VMRAY_URL | VMRay | The URL of the VMRay Platform instance | https://eu.cloud.vmray.com |
| VMRAY_API_KEY | VMRay | The API key to be used for the queries |  |
| VMRAY_VERIFY_CERT | VMRay | Whether the certificate shall be validated | true |
| VMRAY_SLEEP_INTERVAL | VMRay | The amount of time for which the script will sleep between consecutive result queries for a submission | 1 |
   
## Execution

Run the script using
```sh
python tie_file_retriever_multi.py
```

## Video

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/C5DMJbBT3yk/0.jpg)](https://youtu.be/C5DMJbBT3yk)

https://youtu.be/C5DMJbBT3yk

## Feedback

Please provide any feedback or ideas :).
