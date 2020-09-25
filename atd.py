#!/usr/bin/env python3.7
# Written by mohlcyber 31/10/2019 v.0.1

import os
import sys
import base64
import json
import requests
import time

from dotenv import load_dotenv

load_dotenv(verbose=True)


class ATD:
    def __init__(self, filename, data):
        self.ip = os.getenv("ATD_IP")
        self.url = "https://" + self.ip + "/php/"
        self.verify = False
        creds = base64.b64encode(
            (os.getenv("ATD_USER") + ":" + os.getenv("ATD_PW")).encode()
        )
        self.headers = self._auth(creds)

        self.profile = os.getenv("ATD_PROFILE")
        if self.profile is None:
            self.profile = "1"
        timeout = os.getenv("ATD_TIMEOUT")
        if timeout is None:
            timeout = 600
        self.timeout = int(timeout)

        self.filename = filename
        self.data = data

    def _auth(self, creds):
        try:
            sessionheaders = {
                "VE-SDK-API": creds,
                "Content-Type": "application/json",
                "Accept": "application/vnd.ve.v1.0+json",
            }
            res = requests.get(
                self.url + "session.php", headers=sessionheaders, verify=self.verify
            )

            if res.status_code == 200:
                results = res.json()["results"]
                tmp_headers = results["session"] + ":" + results["userId"]

                headers = {
                    "VE-SDK-API": base64.b64encode(tmp_headers.encode()),
                    "Accept": "application/vnd.ve.v1.0+json",
                    "accept-encoding": "gzip;q=0,deflate,sdch",
                }
                print(
                    "ATD STATUS: Successful authenticated {0}.".format(
                        os.getenv("ATD_USER")
                    )
                )
                return headers
            else:
                print(
                    "ATD ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def submit_file(self):
        data = {"data": {"vmProfileList": self.profile, "submitType": "0"}}

        try:
            files = {"amas_filename": (self.filename, self.data)}

            res = requests.post(
                self.url + "fileupload.php",
                headers=self.headers,
                files=files,
                data={"data": json.dumps(data)},
                verify=self.verify,
            )

            if res.status_code == 200:
                for result in res.json()["results"]:
                    taskid = result["taskId"]
                    print(
                        "ATD STATUS: Successful submitted File. TaskID {0}".format(
                            str(taskid)
                        )
                    )
                    return taskid
            else:
                print(
                    "ATD ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def get_status(self, taskid):
        payload = {"iTaskId": taskid}
        status = True

        try:
            start = time.time()

            while status is True:
                elapsed = time.time() - start

                if elapsed > self.timeout:
                    print("ATD ERROR: Timeout arrived. Stopping...")
                    self.logout()
                    sys.exit(1)

                res = requests.get(
                    self.url + "samplestatus.php",
                    params=payload,
                    headers=self.headers,
                    verify=self.verify,
                )

                if res.status_code == 200:
                    state = res.json()["results"]["istate"]

                    if state == 1 or state == 2:
                        print(
                            "ATD STATUS: Analysis done with TaskID: {0}. Trying to get report.".format(
                                str(taskid)
                            )
                        )
                        time.sleep(10)
                        status = False
                    else:
                        print(
                            "ATD STATUS: Analysis not done with TaskID: {0}. Status: {1}".format(
                                str(taskid), res.json()
                            )
                        )
                        time.sleep(120)
                else:
                    print(
                        "ATD ERROR: Something went wrong in {0}. Error: {1}".format(
                            sys._getframe().f_code.co_name, str(res.text)
                        )
                    )
                    sys.exit()

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def get_report(self, taskid):
        payload = {"iTaskId": taskid, "iType": "json"}
        try:
            res = requests.get(
                self.url + "showreport.php",
                params=payload,
                headers=self.headers,
                verify=self.verify,
            )
            if res.status_code == 200:
                # print(res.json())
                result = res.json()["Summary"]["Verdict"]["Description"]
                print("ATD SUCCESS: {0}".format(result))
            else:
                print(
                    "ATD ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def logout(self):
        try:
            res = requests.delete(
                self.url + "session.php", headers=self.headers, verify=self.verify
            )
            if res.status_code == 200:
                print(
                    "ATD STATUS: Successful logged out {0}.".format(
                        os.getenv("ATD_USER")
                    )
                )
            else:
                print(
                    "ATD ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "ATD ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def run(self):
        taskid = self.submit_file()
        self.get_status(taskid)
        self.get_report(taskid)
        self.logout()


if __name__ == "__main__":
    # For manual file submission to McAfee ATD
    filename = "news.exe"
    data = open("news.exe", "rb")
    ATD(filename, data).run()