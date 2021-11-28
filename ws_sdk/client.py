import copy
import logging
import os
import subprocess
import json
from typing import Union
from pkg_resources import parse_version

from ws_sdk import ws_utilities, ws_errors
from ws_sdk.ws_constants import *
from ws_sdk._version import __version__


class WSClient:
    def __init__(self,
                 user_key: str,
                 token: str,
                 token_type: str = ORGANIZATION,
                 url: str = None,
                 ua_path: str = DEFAULT_UA_PATH,
                 ua_jar_with_path: str = None,
                 skip_ua_update: bool = False,
                 tool_details: tuple = ("ps-sdk", __version__)
                 ):
        if token_type is ORGANIZATION:
            self.ua_path = ua_path
            self.ua_path_whitesource = os.path.join(self.ua_path, "whitesource")
            self.java_temp_dir = ua_path
            self.ua_jar_f_with_path = ua_jar_with_path if ua_jar_with_path else os.path.join(ua_path, UA_JAR_F_N)
            # UA configuration
            # self.ua_conf_f_with_path = ua_conf_with_path if ua_conf_with_path else os.path.join(ua_path, UA_CONF_FNAME)
            # self.ua_conf = ws_utilities.convert_ua_conf_f_to_vars(self.ua_conf_f_with_path) # Enable to generate class members from conf file
            self.ua_conf = ws_utilities.WsConfiguration()
            self.ua_conf.apiKey = token
            self.ua_conf.userKey = user_key
            self.ua_conf.wss_url = f"{ws_utilities.get_full_ws_url(url)}/agent"
            self.ua_conf.noConfig = True
            self.ua_conf.checkPolicies = False
            self.ua_conf.includes = {"**/*.c", "**/*.cc", "**/*.cp", "**/*.cpp", "**/*.cxx", "**/*.c++", "**/*.h", "**/*.hpp", "**/*.hxx"}
            self.ua_conf.scanComment = f"agent:{tool_details[0]};agentVersion:{tool_details[1]}"
            if logging.root.level == logging.DEBUG:
                self.ua_conf.logLevel = "debug"

            if self.is_latest_ua_semver() or skip_ua_update:
                logging.debug("Skipping WhiteSource Unified Agent update")
            else:
                logging.info("A new WhiteSource Unified Agent exists. Downloading the latest ")
                ws_utilities.init_ua(self.ua_path)
        else:
            logging.error("Unsupported organization type. Only Organization type is supported")

    def __execute_ua(self,
                     options: str,
                     ua_conf: ws_utilities.WsConfiguration = None):
        def __handle_ws_client_errors():
            if output.returncode == 0:
                logging.debug(f"UA executed successfully. Return Code {output.returncode}. Message: {output.stdout.decode('utf-8')}")
            elif output.returncode == -2:
                raise ws_errors.WsSdkClientPolicyViolation(output.returncode, output.stderr.decode('utf-8'))
            else:
                raise ws_errors.WsSdkClientGenericError(output.returncode, output.stderr.decode('utf-8'))
        """
        Executes the UA
        :param options: The options to pass the UA (that are not pass as env vars)
        :param ua_conf:
        :return: tuple of return code integer and str with ua output
        :rtype: tuple
        """
        if ua_conf is None:
            ua_conf = self.ua_conf
        command = f"java -Djava.io.tmpdir={self.java_temp_dir} -jar {self.ua_jar_f_with_path} {options}"
        logging.debug(f"Running command: {command}")
        env = ws_utilities.generate_conf_ev(ua_conf)
        logging.debug(f"UA Environment Variables: {env}")
        output = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        __handle_ws_client_errors()

        return output.stdout.decode('utf-8')

    def execute_scan(self,
                     scan_dir: Union[list, str],
                     project_token: str = None,
                     product_token: str = None,
                     product_name: str = None,
                     offline: bool = None,
                     comment: str = None):
        """
        Execute scan on dir(s)
        :param scan_dir: the dir(s) to scan (comma seperated if multiple)
        :param project_token: WS Project token to associate scan with
        :param product_token:WS Product token to associate scan with
        :param product_name: WS Product name to associate scan with
        :param offline: Whether to load an offline request or actually scan
        :param comment: Ability to add comment to: "Last Scan Comments"
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
        target = self.get_target(project_token, product_token, product_name)

        if target and existing_dirs:
            logging.info(f"Scanning Dir(s): {existing_dirs} to {target[0]}: {target[1]}")
            local_ua_all_conf = copy.copy(self.ua_conf)

            if offline is not None:
                local_ua_all_conf.Offline = offline

            self.__execute_ua(f"-d {existing_dirs} -{target[0]} {target[1]}", local_ua_all_conf)
        else:
            logging.warning("Nothing was scanned")

        if not existing_dirs:
            logging.error(f"Directory: {existing_dirs} was not found")
        if not target:
            logging.error("At least one value should be configured: productName, productToken or projectToken")

    def upload_offline_request(self,
                               offline_request: Union[dict, str],
                               project_token: str = None,
                               product_token: str = None,
                               product_name: str = None):
        """
        Method to upload an offline request to WS
        :param offline_request: can accept full path to update file of dict
        :param project_token: target project token
        :param product_token: target product token
        :param product_name: target project name
        """
        target = self.get_target(project_token, product_token, product_name)
        if target:
            logging.info(f"Uploading offline request to {target[0]} - {target[1]}")
            if isinstance(offline_request, dict):
                file_path = os.path.join(self.ua_path, "update_request_tmp.json")
                with open(file_path, 'w') as fp:
                    fp.write(json.dumps(offline_request))
            else:
                file_path = offline_request

            self.__execute_ua(f"-requestFiles \"{file_path}\" -{target[0]} {target[1]}", self.ua_conf)
        else:
            logging.error("No target was found")

    def get_target(self,
                   project_token: str,
                   product_token: str,
                   product_name: str) -> tuple:
        target = None
        if project_token:
            target = ("projectToken", project_token)
        elif product_token:
            target = ("productToken", product_token)
        elif product_name:
            target = ("product", product_name)

        return target

    def get_local_ua_semver(self):
        local_semver = self.__execute_ua("-v").strip('\r\n')
        logging.debug(f"Local WhiteSource Unified Agent version {local_semver}")

        return local_semver

    def is_latest_ua_semver(self) -> bool:
        return parse_version(self.get_local_ua_semver()) >= parse_version(ws_utilities.get_latest_ua_release_version())

    def __get_ua_output(self, f) -> dict:
        with open(os.path.join(self.ua_path_whitesource, f), 'r') as fp:
            file_content = fp.read()

        return json.loads(file_content)

    def get_ua_scan_output(self) -> dict:
        return self.__get_ua_output("update-request.txt")

    def get_policy_rejection_summary(self) -> dict:
        return self.__get_ua_output("policyRejectionSummary.json")

    def get_check_policies(self) -> dict:
        return self.__get_ua_output("checkPolicies-json.txt")

    def get_scan_project_details(self) -> dict:
        return self.__get_ua_output("scanProjectDetails.json")

    def add_scan_comment(self,
                         key: str,
                         value: str,
                         ua_conf=None):
        """
        Method to add data into comments. Each top section is seperated by ';' and presented as key : value(e.g. top_key1=top_value1;top_key2=top_value2
        :param key: the key of the data
        :param value: the value of the data
        :param ua_conf: the UA configuration object to use (None meaning it will change self).
        """
        if not ua_conf:
            ua_conf = self.ua_conf

        if ua_conf.scanComment:
            ua_conf.scanComment += ';'

        ua_conf.scanComment += f"{key}:{value}"
