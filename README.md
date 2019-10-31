# McAfee TIE Multisandbox integration
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This integration allows you to submit files from McAfee TIE to multiple sandboxes.

TIE by default is able to submit files to McAfee Advanced Threat Defense (ATD) for file analysis only.
McAfee TIE acts as a hash repository with multiple reputation information. As soon an Endpoint executes an unknown file, TIE will request the file from the endpoint for file analysis and submit this file to ATD.

This integration simulates the McAfee ATD API's, receives the file from McAfee TIE and submits files to various sandboxes for multi sandbox analysis. In this example TIE will submit files to two sandboxes (McAfee ATD and Lastline). 

The different sandbox results will update TIE via ATD Reputation and External/Enterprise reputation.
Adding multiple third party sandboxes would require a reputation calculation.

## Component Description
**McAfee Threat Intelligence Exchange (TIE)** acts as a reputation broker to enable adaptive
threat detection and response. https://www.mcafee.com/enterprise/en-us/products/threat-intelligence-exchange.html

**McAfee Advanced Threat Defense (ATD)** is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides local threat intelligence. ATD exports IOC data in STIX format in several ways including the DXL.
https://www.mcafee.com/in/products/advanced-threat-defense.aspx

**Lastline Analyst** provides threat analysts and incident response teams with the advanced malware inspection and isolation environment they need to safely execute advanced malware samples and understand their behavior. 
https://www.lastline.com/solutions/analyst/

## Prerequisites
