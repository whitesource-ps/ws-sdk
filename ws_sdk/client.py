import copy
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
                 url: str = None,
                 ua_path: str = DEFAULT_UA_PATH,
                 ua_conf_with_path: str = None,
                 ua_jar_with_path: str = None):

        if token_type is ORGANIZATION:
            self.ua_path = ua_path
            self.ua_path_whitesource = os.path.join(self.ua_path, "whitesource")
            self.java_temp_dir = ua_path
            self.ua_jar_f_with_path = ua_jar_with_path if ua_jar_with_path else os.path.join(ua_path, UA_JAR_FNAME)
            self.ua_conf_f_with_path = ua_conf_with_path if ua_conf_with_path else os.path.join(ua_path, UA_CONF_FNAME)
            # UA configuration
            self.ua_all_conf = ws_utilities.convert_ua_conf_f_to_vars(self.ua_conf_f_with_path)
            self.ua_all_conf.apiKey = token
            self.ua_all_conf.userKey = user_key
            self.ua_all_conf.wss_url = f"{ws_utilities.get_full_ws_url(url)}/agent"
            # self.ua_all_conf.whiteSourceFolderPath = self.ua_path
            self.ua_all_conf.Offline = True
            self.ua_all_conf.noConfig = True
            if logging.root.level == logging.DEBUG:
                self.ua_all_conf.logLevel = "debug"
        else:
            logging.error("Unsupported organization type. Only Organization type is supported")

    def __execute_ua(self,
                     options: str,
                     ua_conf: dict) -> tuple:
        """
        Executes the UA
        :param options: The options to pass the UA (that are not pass as env vars)
        :param ua_conf:
        :return: tuple of return code integer and str with ua output
        :rtype: tuple
        """
        command = f"java -Djava.io.tmpdir={self.java_temp_dir} -jar {self.ua_jar_f_with_path} {options}"
        logging.debug(f"Running command: {command}")
        env = ws_utilities.generate_conf_ev(ua_conf)
        logging.debug(f"UA Environment Variables: {env}")
        output = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        return output.returncode, output.stdout.decode('utf-8')

    def execute_scan(self,
                     scan_dir: Union[list, str],
                     project_token: str = None,
                     product_token: str = None,
                     product_name: str = None,
                     offline: bool = None):
        """
        Execute scan on dir(s)
        :param scan_dir: the dir(s) to scan (comma seperated if multiple)
        :param project_token: WS Project token to associate scan with
        :param product_token:WS Product token to associate scan with
        :param product_name: WS Product name to associate scan with
        :param offline:
        :return:
        """
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
            local_ua_all_conf = copy.copy(self.ua_all_conf)

            if offline is not None:
                local_ua_all_conf.Offline = offline

            output = self.__execute_ua(f"-d {existing_dirs} {target}", local_ua_all_conf)
            logging.debug(f"UA output: {output}")
        else:
            logging.warning("Nothing was scanned")

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
        output = self.__execute_ua("-v")
        local_semver = output.strip('\r\n')
        logging.debug(f"WS Unified Agent version {local_semver}")

        return local_semver

    def __get_output(self, f):
        with open(f, 'r') as fp:
            file_content = fp.read()

        return json.loads(file_content)

    def get_ua_scan_output(self) -> dict:
        ua_file_path = os.path.join(self.ua_path_whitesource, "update-request.txt")
        return self.__get_output(ua_file_path)

    def get_policy_rejection_summary(self) -> dict:
        ua_file_path = os.path.join(self.ua_path_whitesource, "policyRejectionSummary.json")
        return self.__get_output(ua_file_path)

    def get_check_policies(self) -> dict:
        ua_file_path = os.path.join(self.ua_path_whitesource, "checkPolicies-json.txt")
        return self.__get_output(ua_file_path)

    def get_scan_project_details(self) -> dict:
        ua_file_path = os.path.join(self.ua_path_whitesource, "scanProjectDetails.json")
        return self.__get_output(ua_file_path)
