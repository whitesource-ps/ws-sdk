from logging import getLogger

from ws_sdk.app import WSApp
from ws_sdk.client import WSClient

logger = getLogger(__name__)


class WS(WSApp, WSClient):

    def __init__(self, **kwargs):
        self.ws_app = WSApp.__init__(self, **kwargs)
        self.ws_client = WSClient.__init__(self, **kwargs)
