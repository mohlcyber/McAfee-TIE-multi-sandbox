# McAfee TIE multi-sandbox integration
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This integration allows you to submit files from McAfee TIE to multiple sandboxes.

TIE by default is able to submit files to McAfee Advanced Threat Defense (ATD) for file analysis only.
McAfee TIE acts as a hash repository with multiple reputation information. As soon an Endpoint executes an unknown file, TIE will request the file from the endpoint for file analysis and submit this file to ATD.

This integration simulates the McAfee ATD API's, receives the file from McAfee TIE and submits files to various sandboxes for multi sandbox analysis. In this example TIE will submit files to two sandboxes (McAfee ATD and Lastline). 

The different sandbox results will update TIE via ATD Reputation and External/Enterprise reputation.
Adding multiple third party sandboxes would require a reputation calculation.

<img width="1126" alt="Screenshot 2019-10-31 at 14 33 00" src="https://user-images.githubusercontent.com/25227268/67951221-614f8b00-fbeb-11e9-8ae8-03c4058a9d49.png">

## Component Description
**McAfee Threat Intelligence Exchange (TIE)** acts as a reputation broker to enable adaptive
threat detection and response. https://www.mcafee.com/enterprise/en-us/products/threat-intelligence-exchange.html

**McAfee Advanced Threat Defense (ATD)** is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides local threat intelligence. ATD exports IOC data in STIX format in several ways including the DXL.
https://www.mcafee.com/in/products/advanced-threat-defense.aspx

**Lastline Analyst** provides threat analysts and incident response teams with the advanced malware inspection and isolation environment they need to safely execute advanced malware samples and understand their behavior. 
https://www.lastline.com/solutions/analyst/

## Configuration
1. Create Web Server Certificates for TLS. e.g.

   ```openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem```

2. Change the PATH to the the new generated Web Server Certificates (line 20 in tie_file_retriever.py)

3. For ATD submission: Change the ATD IP, Username, Password and ProfileID (line 12 - 15 in atd.py)

   <img width="240" alt="Screenshot 2019-10-31 at 13 00 25" src="https://user-images.githubusercontent.com/25227268/67945112-6d811b80-fbde-11e9-9a9f-4a6f6a38b724.png">

4. For Lastline submission: Change the Lastline User and Password (line 14 and 15 in lastline.py)

   <img width="399" alt="Screenshot 2019-10-31 at 13 10 36" src="https://user-images.githubusercontent.com/25227268/67945706-dddc6c80-fbdf-11e9-98af-4f37a06e9b4a.png">
   
   To update the TIE External Reputation with the Lastline analysis results - install the McAfee DXL Client and DXL TIE Client libraries.
   
   OpenDXL SDK ([Link](https://github.com/opendxl/opendxl-client-python))
   ```sh
   git clone https://github.com/opendxl/opendxl-client-python.git
   cd opendxl-client-python/
   python setup.py install
   ```

   OpenDXL TIE SDK ([Link](https://github.com/opendxl/opendxl-tie-client-python))
   ```sh
   git clone https://github.com/opendxl/opendxl-tie-client-python.git
   cd opendxl-tie-client-python/
   python setup.py install
   ```
   
   Make sure to authorize the new created certificates in ePO to set McAfee TIE Reputations 
   ([Link].(https://opendxl.github.io/opendxl-tie-client-python/pydoc/basicsetreputationexample.html)).

   Make sure that the FULL PATH to the dxlclient.config file is entered in line 17 (lastline.py).
   
5. To submit files from TIE to the multi-sandbox service change the IP, Username and Password (aligned to the username and password in tie_file_retriever.py line 22 and 23) in ePO to point to the new created service. Also make sure that the polling target in the polling settings is set to None!

   <img width="1440" alt="Screenshot 2019-10-31 at 13 26 12" src="https://user-images.githubusercontent.com/25227268/67946645-0ebda100-fbe2-11e9-9ae3-8b4e33f3c72e.png">
   
## Execution

run the script 
```sh
python3.8 tie_file_retriever_multi.py
```

## Video

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/C5DMJbBT3yk/0.jpg)](https://youtu.be/C5DMJbBT3yk)

https://youtu.be/C5DMJbBT3yk

## Feedback

Please provide any feedback or ideas :).
