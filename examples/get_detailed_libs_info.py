import logging
import os
import sys

from ws_sdk.web import WS

logging.basicConfig(level=logging.INFO, stream=sys.stdout)

ws_url = os.environ['WS_URL']
ws_org_token = os.environ['WS_ORG_TOKEN']
ws_user_key = os.environ['WS_USER_KEY']


if __name__ == '__main__':
    c_org = WS(url=ws_url, user_key=ws_user_key, token=ws_org_token)
    tmp = c_org.get_scopes()
    print(tmp)

