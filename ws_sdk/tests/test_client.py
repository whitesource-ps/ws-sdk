import logging
import os
import pathlib
import sys
from unittest import TestCase
from unittest.mock import patch

from ws_sdk.client import WSClient


class TestWSClient(TestCase):
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


class TestWS(TestCase):
    @patch('ws_sdk.client.WSClient.is_latest_ua_semver')
    @patch('ws_sdk.ws_utilities.convert_ua_conf_f_to_vars')
    def setUp(self, mock_convert_ua_conf_f_to_vars, mock_is_latest_ua_semver):
        logging.basicConfig(level=logging.DEBUG)
        pathlib.Path("ws_constants.DEFAULT_UA_PATH").mkdir(parents=True, exist_ok=True)
        mock_convert_ua_conf_f_to_vars.return_value.apiKey = None
        mock_convert_ua_conf_f_to_vars.return_value.userKey = None
        mock_convert_ua_conf_f_to_vars.return_value.wss_url = None
        mock_is_latest_ua_semver.return_value = True
        self.client = WSClient(user_key=os.environ['WS_USER_KEY'],
                               token=os.environ['WS_ORG_TOKEN'])

    def test_get_local_ua_semver(self):
        ua_ret_t = "21.6.3"
        with patch.object(self.client, "_WSClient__execute_ua", return_value=ua_ret_t) as method:
            res = self.client.get_local_ua_semver()

            self.assertEqual(res, ua_ret_t)


if __name__ == '__main__':
    TestCase.unittest.main()

