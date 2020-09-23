#!/usr/bin/env python3.7
# Written by mohlcyber 31/10/2019 v.0.1

import sys
import os
import time
import requests

from dxltieclient.constants import TrustLevel
from tie_dxl_connector import TIE

from dotenv import load_dotenv

load_dotenv(verbose=True)


class LASTLINE:
    def __init__(self, filename, data):
        self.url = os.getenv("LASTLINE_URL")
        self.verify = True

        self.filename = filename
        self.filedata = data

        creds = {
            "username": os.getenv("LASTLINE_USER"),
            "password": os.getenv("LASTLINE_PW"),
        }
        self._login(creds)
        self.params = {}

    def _login(self, creds):
        try:
            res = requests.post(self.url + "/login", data=creds, verify=self.verify)
            if res.status_code == 200:
                self.cookie = res.cookies
                print(
                    "LASTLINE STATUS: Successful authenticated {}.".format(
                        creds["username"]
                    )
                )
            else:
                print(
                    "LASTLINE ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "LASTLINE ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def submit_file(self):
        try:
            self.params["filename"] = self.filename
            file = {"file": self.filedata}

            res = requests.post(
                self.url + "/analysis/submit_file",
                cookies=self.cookie,
                params=self.params,
                files=file,
                verify=self.verify,
            )

            if res.status_code == 200:
                uuid = res.json()["data"]["task_uuid"]
                self.params = {"uuid": uuid}
                print(
                    "LASTLINE STATUS: Successful submitted File. Submission task uuid {0}".format(
                        str(uuid)
                    )
                )
            else:
                print(
                    "LASTLINE ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "LASTLINE ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def get_status(self):
        try:
            status = False
            while status is False:
                res = requests.get(
                    self.url + "/analysis/get_progress",
                    cookies=self.cookie,
                    params=self.params,
                    verify=self.verify,
                )

                if res.status_code == 200:
                    res_data = res.json()["data"]

                    if res_data["completed"] == 1:
                        status = True
                        print(
                            "LASTLINE STATUS: File analysis finished. Trying to retrieve result."
                        )
                    else:
                        print(
                            "LASTLINE STATUS: File analysis not finished. Status: {0}".format(
                                res.json()
                            )
                        )
                        time.sleep(120)
                else:
                    print(
                        "LASTLINE ERROR: Something went wrong in {0}. Error: {1}".format(
                            sys._getframe().f_code.co_name, str(res.text)
                        )
                    )
                    sys.exit()
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "LASTLINE ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def get_result(self):
        try:
            res = requests.get(
                self.url + "/analysis/get_result",
                cookies=self.cookie,
                params=self.params,
                verify=self.verify,
            )

            if res.status_code == 200:
                score = res.json()["data"]["score"]
                md5 = res.json()["data"]["analysis_subject"]["md5"]
                sha1 = res.json()["data"]["analysis_subject"]["sha1"]
                sha256 = res.json()["data"]["analysis_subject"]["sha256"]

                print("LASTLINE RESULT: File Score is {0}.".format(str(score)))
                print("LASTLINE STATUS: Trying to set DXL External Reputation.")
                TIE().set_rep(self.filename, self._map_level(score), md5, sha1, sha256)
            else:
                print(
                    "LASTLINE ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "LASTLINE ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def _map_level(self, score):
        if score < 30:
            level = TrustLevel.MIGHT_BE_TRUSTED
        elif score >= 30 or score < 70:
            level = TrustLevel.MOST_LIKELY_MALICIOUS
        else:
            level = TrustLevel.KNOWN_MALICIOUS
        return level

    def logout(self):
        try:
            res = requests.get(
                self.url + "/logout", cookies=self.cookie, verify=self.verify
            )
            if res.status_code == 200:
                print(
                    "LASTLINE STATUS: Successful logged out {0}.".format(
                        os.getenv("LASTLINE_USER")
                    )
                )
            else:
                print(
                    "LASTLINE ERROR: Something went wrong in {0}. Error: {1}".format(
                        sys._getframe().f_code.co_name, str(res.text)
                    )
                )
                sys.exit()
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "LASTLINE ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )
            sys.exit()

    def run(self):
        self.submit_file()
        self.get_status()
        self.get_result()
        self.logout()


if __name__ == "__main__":
    # For manual file submission to Lastline Analyst
    filename = "news.exe"
    data = open("news.exe", "rb")
    LASTLINE(filename, data).run()
