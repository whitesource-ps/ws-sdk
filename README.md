![Logo](https://whitesource-resources.s3.amazonaws.com/ws-sig-images/Whitesource_Logo_178x44.png)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/whitesource-ps/ws-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/whitesource-ps/ws-sdk/actions/workflows/ci.yml)
[![Python 3.7](https://upload.wikimedia.org/wikipedia/commons/thumb/8/8c/Blue_Python_3.6%2B_Shield_Badge.svg/86px-Blue_Python_3.6%2B_Shield_Badge.svg.png)](https://www.python.org/downloads/release/python-360/)
![PyPI](https://img.shields.io/pypi/v/ws-sdk?style=plastic)

# [WhiteSource Python SDK](https://github.com/whitesource-ps/ws-sdk)
SDK written in Python to simplify access to WhiteSource resources

The SDK contains the following modules:
* **web** - Module for accessing WhiteSource Application (reports, administration, etc...).
* **client** - UA wrapper layer (download UA, execute scan, read UA output files...).  

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
# Web (WhiteSource Application)
from ws_sdk.web import WS
ws = WS(api_url="WS_URL", user_key="USER_KEY", token="ORG_TOKEN")
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
out = ws_client.execute_scan(scan_dir="/PATH/TO/DIR", project_token="PROJ_TOKEN")
# Read scan artifcat's policy rejection summary 
pol_rej = ws_client.get_policy_rejection_summary()
```
