[![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)](https://www.whitesourcesoftware.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sdk/actions/workflows/ci.yml)
[![Python 3.7](https://upload.wikimedia.org/wikipedia/commons/7/76/Blue_Python_3.7%2B_Shield_Badge.svg)
[![PyPI](https://img.shields.io/pypi/v/ws-sdk?style=plastic)](https://pypi.org/project/ws-sdk/)

# [WhiteSource Python SDK](https://github.com/whitesource-ps/ws-sdk)
SDK written in Python to simplify access to WhiteSource resources

The SDK contains the following modules:
* **web** - Module for accessing WhiteSource Application (reports, administration, etc...).
* **client** - UA wrapper layer (download UA, execute scan, read UA output files...).  

## Supported Operating Systems
- **Linux (Bash):**	CentOS, Debian, Ubuntu, RedHat
- **Windows (PowerShell):**	10, 2012, 2016

## How to install package from PyPi
1. Obtain connection details from WS Application (Home > Admin > Integration).
1. Install package from Pypi: `pip install ws-sdk` .

## How to build and install package from source (for developers)
1. Download the code: `git clone https://github.com/whitesource-ps/ws-sdk.git`.
1. Build wheel package `python setup.py bdist_wheel` .
1. Download wheel from GitHub and install : `pip install ws-sdk*.whl` .


## Execution

```python
# Unified (can do both WSApp and WSClient)
from ws_sdk.web import WS
ws = WS(api_url="WS_URL", user_key="USER_KEY", token="ORG_TOKEN")

# Web (WhiteSource Application)
from ws_sdk.app import WSApp
ws = WSApp(api_url="WS_URL", user_key="USER_KEY", token="ORG_TOKEN")
# Get alerts 
all_alerts = ws.get_alerts()
# Get vulnerabilities report in XLSX format
vul_report = ws.get_vulnerability(report=True)
# Get all projects ()
project_list = ws.get_projects()
# Create user in the organization
ws.create_user(name='USER_TEST1', email="USER_TEST1@EMAIL.COM", inviter_email="INVITER@EMAIL.COM")

# Client (WhiteSource Unified Agent)
from ws_sdk.client import WSClient

ws_client = WSClient(api_url="WS_URL", user_key="USER_KEY", token="ORG_TOKEN", ua_path="/UA/WORKING/DIR")
# Download latest UA jar and conf file
ws_client.download_ua()
# Execute scan into defined project token
out = ws_client.scan(scan_dir="/PATH/TO/DIR", project_token="PROJ_TOKEN", product_token="PROD_TOKEN")
# Read scan artifact's policy rejection summary 
pol_rej = ws_client.get_policy_rejection_summary()
```
