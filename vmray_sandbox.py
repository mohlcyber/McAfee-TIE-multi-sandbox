#!/usr/bin/env python3.7
# Written by mohlcyber 31/10/2019 v.0.1

import sys
import os
import time
import requests
import logging

from dxltieclient.constants import TrustLevel
from tie_dxl_connector import TIE

from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError

from dotenv import load_dotenv

load_dotenv(verbose=True)

DEFAULT_SLEEP_INTERVAL = 1


class VMRAY:
    def __init__(self, filename, data):
        self.api_client = VMRayRESTAPI(
            server=os.getenv("VMRAY_URL"),
            api_key=os.getenv("VMRAY_API_KEY"),
            verify_cert=True if os.getenv("VMRAY_VERIFY_CERT") == "true" else False,
        )

        self.filename = filename
        self.filedata = data

    def _submit_file(self):
        """
        Submit the file with which this instance has been initiated to VMRay.
        :returns: A list of submissions that has been created for the file
        """
        try:
            logging.info("Submitting file %s to VMRay", self.filename)
            open(self.filename, "wb").write(self.filedata)
            with open(self.filename, "rb") as sample_file:
                params = {"sample_file": sample_file, "reanalyze": True}
                data = self.api_client.call("POST", "/rest/sample/submit", params)
                return data["submissions"]
        except VMRayRESTAPIError as e:
            logging.error(
                "Encountered an error during the submission of %s: %s", self.filename, e
            )
            sys.exit()
        finally:
            os.remove(self.filename)

    def _wait_for_submissions(self, submissions):
        """
        Wait for all given submissions to be finished.
        :param submissions: A list of submissions that has been created as a result of the _submit_file operation
        :returns: The updated list of submissions which have already been finished
        """
        sleep_interval = os.getenv("VMRAY_SLEEP_INTERVAL")
        if sleep_interval is None:
            sleep_interval = DEFAULT_SLEEP_INTERVAL
        else:
            sleep_interval = int(sleep_interval)
        updated_submissions = []
        while True:
            for submission in submissions:
                try:
                    submission_data = self.api_client.call(
                        "GET", "/rest/submission/{}".format(submission["submission_id"])
                    )
                    if submission_data["submission_finished"]:
                        updated_submissions.append(submission_data)
                        submissions.remove(submission)
                except VMRayRESTAPIError:
                    # try again in case of error
                    break

            if not submissions:
                break
            time.sleep(sleep_interval)
        return updated_submissions

    def _push_result(self, submissions):
        """
        Push the results back to TUE using the DXL client.
        :param submissions: A list of submissions that has been created as a result of the _submit_file operation
        """
        logging.debug("Trying to set DXL External Reputation for VMRay results.")
        # TODO build a composite verdict of all submissions?
        try:
            TIE().set_rep(
                filename=self.filename,
                level=self._map_level(submissions[0]["submission_verdict"]),
                md5=submissions[0]["submission_sample_md5"],
                sha1=submissions[0]["submission_sample_sha1"],
                sha256=submissions[0]["submission_sample_sha256"],
                sandbox="VMRay",
            )
        except Exception as e:
            logging.error(e)

    def _map_level(self, verdict):
        if verdict == "clean":
            level = TrustLevel.MIGHT_BE_TRUSTED
        elif verdict == "suspicious":
            level = TrustLevel.MOST_LIKELY_MALICIOUS
        elif verdict == "malicious":
            level = TrustLevel.KNOWN_MALICIOUS
        else:
            level = TrustLevel.MIGHT_BE_MALICIOUS
        return level

    def run(self):
        submissions = self._submit_file()
        updated_submissions = self._wait_for_submissions(submissions)
        self._push_result(updated_submissions)


if __name__ == "__main__":
    # For manual file submission to VMRAY Platform
    filename = "news.exe"
    data = open(filename, "rb")
    VMRAY(filename, data).run()
