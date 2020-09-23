import os
import sys

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

    def set_rep(self, filename, level, md5, sha1, sha256):
        try:
            with DxlClient(self.config) as client:
                client.connect()
                tie_client = TieClient(client)

                tie_client.set_external_file_reputation(
                    level,
                    {"md5": md5, "sha1:": sha1, "sha256": sha256},
                    filename=filename,
                    comment="External Reputation set from Lastline",
                )

                print(
                    "LASTLINE SUCCESS: Set reputation in TIE for MD5 {0}.".format(
                        str(md5)
                    )
                )

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print(
                "ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}".format(
                    location=__name__,
                    funct_name=sys._getframe().f_code.co_name,
                    line_no=exc_tb.tb_lineno,
                    error=str(e),
                )
            )