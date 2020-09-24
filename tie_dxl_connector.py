import os
import sys
import logging

from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import TrustLevel, HashType, FileProvider

from dotenv import load_dotenv

load_dotenv(verbose=True)


class TIE:
    def __init__(self):
        self.config = DxlClientConfig.create_dxl_config_from_file(
            os.getenv("DXL_CONNECTOR_CLIENT_CONFIG_PATH")
        )

    def _set_reputation(self, tie_client, filename, level, md5, sha1, sha256, sandbox):
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

    def set_rep(self, filename, level, md5, sha1, sha256, sandbox):
        try:
            with DxlClient(self.config) as client:
                client.connect()
                tie_client = TieClient(client)

                # multi-sandbox support: merge results if some are already available
                existing_reputation = tie_client.get_file_reputation(
                    {HashType.SHA256: sha256}
                )
                if existing_reputation and FileProvider.EXTERNAL in existing_reputation:
                    logging.info(
                        "A external reputation verdict has been already present for the sample, will merge the results"
                    )
                    if (
                        level != 0
                        and level
                        < existing_reputation[FileProvider.EXTERNAL]["trustLevel"]
                    ):
                        self._set_reputation(
                            tie_client, filename, level, md5, sha1, sha256, sandbox
                        )
                    else:
                        logging.info(
                            "New reputation level was higher than what is already present"
                        )
                else:
                    self._set_reputation(
                        tie_client, filename, level, md5, sha1, sha256, sandbox
                    )

        except Exception as e:
            logging.error(
                "ERROR setting the reputation in TIE for MD5 %s using sandbox %s: %s",
                str(md5),
                sandbox,
                e,
            )
