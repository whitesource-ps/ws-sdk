import copy
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
    valid_token = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz12"

    @patch('ws_sdk.client.WSClient.is_latest_ua_semver')
    @patch('ws_sdk.ws_utilities.convert_ua_conf_f_to_vars')
    def setUp(self, mock_convert_ua_conf_f_to_vars, mock_is_latest_ua_semver):
        logging.basicConfig(level=logging.DEBUG)
        pathlib.Path("ws_constants.DEFAULT_UA_PATH").mkdir(parents=True, exist_ok=True)
        mock_convert_ua_conf_f_to_vars.return_value.apiKey = None
        mock_convert_ua_conf_f_to_vars.return_value.userKey = None
        mock_convert_ua_conf_f_to_vars.return_value.ws_url = None
        mock_is_latest_ua_semver.return_value = True
        self.client = WSClient(user_key=os.environ.get('WS_USER_KEY', self.valid_token),
                               token=os.environ.get('WS_ORG_TOKEN', self.valid_token))

    @patch('ws_sdk.client.WSClient._execute_ua')
    def test_get_local_ua_semver(self, mock_execute_ua):
        ua_ret_t = "21.6.3"
        mock_execute_ua.return_value = (0, ua_ret_t)
        res = self.client.get_local_ua_semver()

        self.assertEqual(res, ua_ret_t)

    def test_add_scan_comment(self):
        key = "key1"
        value = "value1"
        compared_ua_conf = copy.copy(self.client.ua_conf)
        self.client.add_scan_comment(key=key, value=value)

        self.assertEqual(f"{compared_ua_conf.scanComment};key1:value1", self.client.ua_conf.scanComment)

    def test_add_scan_comment(self):
        key = "key1"
        value = "value1"
        compared_ua_conf = copy.copy(self.client.ua_conf)
        self.client.add_scan_comment(key=key, value=value)

        self.assertEqual(f"{compared_ua_conf.scanComment};key1:value1", self.client.ua_conf.scanComment)


if __name__ == '__main__':
    TestCase.unittest.main()

