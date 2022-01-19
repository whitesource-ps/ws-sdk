from logging import getLogger

from ws_sdk.app import WSApp
from ws_sdk.client import WSClient

logger = getLogger(__name__)


class WS(WSApp, WSClient):
    def __init__(self, **kwargs):
        WSApp.__init__(self, **kwargs)
        WSClient.__init__(self, **kwargs)
