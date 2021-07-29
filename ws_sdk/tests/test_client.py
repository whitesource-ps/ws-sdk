import logging
import os
import sys
from unittest import TestCase
from unittest.mock import patch

from ws_sdk import WSClient


class TestWSClient(TestCase):
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
    ws_url = os.environ['WS_URL']


class TestWS(TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.client = WSClient(url=os.environ.get('WS_URL'),
                               user_key=os.environ['WS_USER_KEY'],
                               token=os.environ['WS_TOKEN'])

    def test_get_latest_ua_release_url(self):
        res = self.client.get_latest_ua_release_url()

        self.assertIsInstance(res['tag_name'], str)

    @patch('ws_sdk.client.WSClient.execute_ua')
    def test_get_local_ua_semver(self, mock_execute_ua):
        ua_ver = "21.6.3"
        mock_execute_ua.return_value = ua_ver
        res = self.client.get_local_ua_semver()

        self.assertEqual(res, ua_ver)


if __name__ == '__main__':
    TestCase.unittest.main()

