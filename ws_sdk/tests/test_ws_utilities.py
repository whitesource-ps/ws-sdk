import logging
import sys
from unittest import TestCase
from ws_sdk import ws_utilities


class TestWsUtilities(TestCase):
    def setUp(self):
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

    def test_get_latest_ua_release_url(self):
        res = ws_utilities.get_latest_ua_release_url()

        self.assertIsInstance(res['tag_name'], str)


if __name__ == '__main__':
    TestCase.unittest.main()

