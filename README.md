![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sdk/actions/workflows/ci.yml)
[![WS Nexus Integration Build and Publish](https://github.com/whitesource-ps/ws-nexus/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-nexus/actions/workflows/ci.yml)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
![PyPI](https://img.shields.io/pypi/v/ws-sdk?style=plastic)

# WhiteSource Python SDK
SDK written in Python to simplify access to WhiteSource resources

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## How to build and install package from source
1. Download the code: `git clone https://github.com/whitesource-ps/ws-sdk.git`
1. Build wheel package `python setup.py bdist_wheel`
1. Download wheel from GitHub and install : `pip install ws-sdk*.whl` 

## How to install package
1. Obtain connection details from WS Application (Home > Admin > Integration)
1. Install package from Pypi: `pip install ws-sdk`

## Execution
```python
from ws_sdk.web import WS
ws = WS(api_url="WS_URL", user_key="USER_KEY", token="ORG_TOKEN")
all_alerts = ws.get_alerts()

scope = ws.get_scope_by_token(token="TOKEN_ID")
```
