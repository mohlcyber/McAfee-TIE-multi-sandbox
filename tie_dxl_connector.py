import os
import sys
import logging

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import TrustLevel

from dotenv import load_dotenv

load_dotenv(verbose=True)


class TIE:
    def __init__(self):
        self.config = DxlClientConfig.create_dxl_config_from_file(
            os.getenv("DXL_CONNECTOR_CLIENT_CONFIG_PATH")
        )

    def set_rep(self, filename, level, md5, sha1, sha256, sandbox):
        try:
            with DxlClient(self.config) as client:
                client.connect()
                tie_client = TieClient(client)

                tie_client.set_external_file_reputation(
                    level,
                    {"md5": md5, "sha1:": sha1, "sha256": sha256},
                    filename=filename,
                    comment="External Reputation set from {}".format(sandbox),
                )

                logging.info(
                    "SUCCESS setting the reputation in TIE for MD5 %s using sandbox %s",
                    str(md5),
                    sandbox,
                )

        except Exception as e:
            logging.error(
                "ERROR setting the reputation in TIE for MD5 %s using sandbox %s: %s",
                str(md5),
                sandbox,
                e,
            )
