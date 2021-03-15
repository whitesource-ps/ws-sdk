![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)

[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![GitHub release](https://img.shields.io/github/release/whitesource-ps/wss-template.svg)](https://github.com/whitesource-ps/wss-template/releases/latest)
![CI](https://github.com/whitesource-ps/ws_sdk/workflows/WS%20Python%20SDK%20Python%20CI/badge.svg)
![ws-sdk](https://img.shields.io/badge/pypi-v1.0.0-blue)
[![Python 3.6](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
[![PyPI version](https://badge.fury.io/py/ws-sdk.svg)](https://badge.fury.io/py/ws-sdk)

# WhiteSource Python SDK
SDK written in Python to simplify access to WhiteSource resources

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## Prerequisites
Prerequisite list

## Instructions
1. Obtain connection details from WS Application (Home > Admin > Integration)
2. Install wheel package


## Execution
```python
from ws_sdk.web import WS
ws = WS(api_url="WS_URL", user_key="USER_KEY", token="ORG_TOKEN")
all_alerts = ws.get_alerts()
```
