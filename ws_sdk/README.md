# ![WS Logo](ws_icon_32x32.png) WS Python SDK

![CI](https://github.com/whitesource-ps/ws_sdk/workflows/WS%20Python%20SDK%20Python%20CI/badge.svg)
![ws-sdk](https://img.shields.io/badge/pypi-v1.0.0-blue)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
[![PyPI version](https://badge.fury.io/py/ws-sdk.svg)](https://badge.fury.io/py/ws-sdk)

# How to use:
1. Obtain connection details from WS Application (Home > Admin > Integration)
2. In python code:
```python
from ws_sdk.web import WS
ws = WS(api_url="WS_URL", user_key="USER_KEY", token="ORG_TOKEN")

# To get alerts as list:
all_alerts = list()
all_alerts = ws.get_alerts()

# To get source files report in Excel format:
all_source_files = ws.get_source_files(report=True)
with open('c:/tmp/all_source_files.xlsx', 'wb') as f:
    f.write(all_source_files)
```