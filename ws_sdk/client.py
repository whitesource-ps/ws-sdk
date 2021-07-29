import logging
import os
import subprocess
import json
from typing import Union

import requests

from ws_sdk import ws_utilities
from ws_sdk.ws_constants import *


class WSClient:
    def __init__(self,
                 user_key: str,
                 token: str,
                 token_type: str = ORGANIZATION,
                 url: str = 'saas',
                 ua_path: str = DEFAULT_UA_PATH,
                 ua_conf_with_path: str = None,
                 ua_jar_with_path: str = None):

        if token_type is ORGANIZATION:
            self.ua_path = ua_path
            self.ua_jar_f_with_path = ua_jar_with_path if ua_jar_with_path else os.path.join(ua_path, UA_JAR_FNAME)
            self.ua_conf_f_with_path = ua_conf_with_path if ua_conf_with_path else os.path.join(ua_path, UA_CONF_FNAME)
            # UA configuration
            self.ua_all_conf = ws_utilities.convert_ua_conf_f_to_vars(self.ua_conf_f_with_path)
            self.ua_all_conf.apiKey = token
            self.ua_all_conf.userKey = user_key
            self.ua_all_conf.wss_url = f"{ws_utilities.get_full_ws_url(url)}/agent"
        else:
            logging.error("Unsupported organization type. Only Organization type is supported")

    def execute_ua(self, options: str):
        command = f"java -jar {self.ua_jar_f_with_path} {options}"
        logging.debug(f"Running command: {command}")
        env = ws_utilities.generate_conf_ev(self.ua_all_conf)
        logging.debug(f"UA Environment Variables: {env}")
        output = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return output.stdout

    def execute_scan(self,
                     scan_dir: Union[list, str],
                     project_token: str = None,
                     product_token: str = None,
                     product_name: str = None):
        def get_existing_paths(s_dir):
            if isinstance(s_dir, str) and os.path.exists(scan_dir):
                ret = s_dir
            else:
                e_dirs = set()
                for d in s_dir:
                    e_dirs.add(d) if os.path.exists(d) else logging.warning(f"Directory: {d} was not found. Skipping")
                ret = ",".join(e_dirs)

            return ret

        existing_dirs = get_existing_paths(scan_dir)
        target = None
        if not existing_dirs:
            logging.error(f"Directory: {existing_dirs} was not found")
        elif project_token:
            target = "-projectToken " + project_token
        elif product_token:
            target = "-productToken " + product_token
        elif product_name:
            target = "-product" + product_name
        else:
            logging.error("At least one value should be configured: productName, productToken or projectToken")

        if target and existing_dirs:
            logging.info(f"Scanning Dir(s): {existing_dirs}")
            output = self.execute_ua(f"-d {existing_dirs} {target}")
            logging.debug(f"UA output: {output}")

    def get_latest_ua_release_url(self) -> dict:
        res = ws_utilities.call_gh_api(url=LATEST_UA_URL)

        return json.loads(res.text)

    def download_ua(self,
                    inc_ua_jar_file: bool = True,
                    inc_ua_conf_file: bool = True):
        def download_ua_file(f_details: tuple):
            path = os.path.join(self.ua_path, f_details[0])
            logging.debug(f"Downloading WS Unified Agent (version: {self.get_latest_ua_release_version()}) to {path}")
            resp = requests.get(url=f_details[1])
            with open(path, 'wb') as f:
                f.write(resp.content)

        if inc_ua_jar_file:
            download_ua_file(UA_JAR)

        if inc_ua_conf_file:
            download_ua_file(UA_CONF)

    def get_latest_ua_release_version(self) -> str:

        return self.get_latest_ua_release_url()['tag_name']

    def get_local_ua_semver(self):
        output = self.execute_ua("-v")
        local_semver = output.strip('\r\n')
        logging.debug(f"WS Unified Agent version {local_semver}")

        return local_semver
