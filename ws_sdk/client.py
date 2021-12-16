import copy
from logging import getLogger
import logging
import os
import json
from typing import Union
from pkg_resources import parse_version

from ws_sdk import ws_utilities, ws_errors
from ws_sdk.ws_constants import *
from ws_sdk._version import __version__, __tool_name__

logger = logging.getLogger(__name__)


class WSClient:
    @staticmethod
    def get_client_api_url(url: str) -> str:
        return url if url.endswith('/agent') else url + '/agent'

    def __init__(self,
                 user_key: str,
                 token: str,
                 token_type: str = ORGANIZATION,
                 url: str = None,
                 java_bin: str = JAVA_BIN,
                 ua_path: str = f"c:/tmp/ws-{__tool_name__}" if sys.platform == "win32" else f"/tmp/{__tool_name__}",
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
            self.ua_conf = ws_utilities.WsConfiguration()
            self.ua_conf.apiKey = token
            self.ua_conf.userKey = user_key
            self.ws_url = f"{ws_utilities.get_full_ws_url(url)}"
            self.java_bin = java_bin if bool(java_bin) else JAVA_BIN
            self.ua_conf.wss_url = self.get_client_api_url(self.ws_url)
            self.ua_conf.log_files_path = self.ua_path
            self.ua_conf.whiteSourceFolderPath = self.ua_path
            self.ua_conf.checkPolicies = False
            self.ua_conf.scanComment = f"agent:{tool_details[0]};agentVersion:{tool_details[1]}"
            self.ua_conf.showProgressBar = False
            # Input validation
            if not ws_utilities.is_java_exists(self.java_bin):
                logger.warning(f"Java: '{java_bin}' was not found")
            if logger.level == logging.DEBUG:
                self.ua_conf.logLevel = "debug"
            else:
                self.ua_conf.log_files_level = "Off"        # Generate logs in files
            if ws_utilities.is_ua_exists(self.ua_jar_f_with_path) and (skip_ua_update or self.is_latest_ua_semver()):
                logger.debug("Skipping WhiteSource Unified Agent update")
            else:
                logger.info("A new WhiteSource Unified Agent exists. Downloading the latest ")
                ws_utilities.init_ua(self.ua_path)
        else:
            logger.error("Unsupported organization type. Only Organization type is supported")

    def _execute_ua(self,
                    options: str,
                    ua_conf: ws_utilities.WsConfiguration = None) -> tuple:
        def _handle_ws_client_errors():
            if output[0] == 0:
                logger.debug(f"UA executed successfully. Return Code {output[0]}. Message: {output[1]}")
            elif output[0] == -2:
                raise ws_errors.WsSdkClientPolicyViolation(output)
            else:
                raise ws_errors.WsSdkClientGenericError(output)
        """
        Executes the UA
        :param options: The options to pass the UA (that are not pass as env vars)
        :param ua_conf:
        :return: tuple of return code integer and str with ua output
        :rtype: tuple
        """
        if ua_conf is None:
            ua_conf = self.ua_conf
        command = f"{self.java_bin}"
        switches = f"-Djava.io.tmpdir={self.java_temp_dir} -jar {self.ua_jar_f_with_path} {options} -noConfig True"  #-noConfig True => configFilePath=DEFAULT
        env = ws_utilities.generate_conf_ev(ua_conf)
        orig_path = os.getcwd()
        os.chdir(self.ua_path)                                                  # TODO CONSIDER PUTTING ON CONSTRUCTOR
        output = ws_utilities.execute_command(command=command, switches=switches, env=env)
        os.chdir(orig_path)
        _handle_ws_client_errors()

        return output

    @staticmethod
    def get_existing_paths(s_dir):
        if isinstance(s_dir, str) and os.path.exists(s_dir):
            ret = s_dir
        else:
            e_dirs = set()
            for d in s_dir:
                e_dirs.add(d) if os.path.exists(d) else logger.warning(f"Directory: {d} was not found. Skipping")
            ret = ",".join(e_dirs)

        return ret

    def scan(self,
             scan_dir: Union[list, str],
             project_token: str = None,
             project_name: str = None,
             product_token: str = None,
             product_name: str = None,
             offline: bool = None,
             comment: str = None,
             include: list = None) -> tuple:
        """
        Execute scan on dir(s)
        :param scan_dir: the dir(s) to scan (comma seperated if multiple)
        :param project_token: WS Project token to associate scan with
        :param project_name: WS Project name to associate scan with
        :param product_token:WS Product token to associate scan with
        :param product_name: WS Product name to associate scan with
        :param offline: Whether to load an offline request or actually scan
        :param comment: Ability to add comment to: "Last Scan Comments"
        :param include: specify list of suffices to scan
        :return: return tuple output and error stream and return code
        """

        existing_dirs = self.get_existing_paths(scan_dir)
        target = self.get_target(project_token, product_token, product_name)

        ret = None
        if not existing_dirs:
            logger.error(f"No valid directories were found in: {scan_dir}")
        elif not (project_token or project_name):
            logger.error("Project name or token must be passed")
        elif not target:
            logger.error("At least one value should be configured: productName, productToken or projectToken")
        elif target and existing_dirs:
            logger.info(f"Scanning Dir(s): {existing_dirs} to {target[0]}: {target[1]}")
            local_ua_all_conf = copy.copy(self.ua_conf)
            self.add_scan_comment(key="comment", value=comment, ua_conf=local_ua_all_conf)

            if offline is not None:
                local_ua_all_conf.Offline = offline

            if include:
                local_ua_all_conf.set_include_suffices_to_scan(include)

            ret = self._execute_ua(f"-d {existing_dirs} -{target[0]} {target[1]}", local_ua_all_conf)
        else:
            logger.warning("Nothing was scanned")

        return ret

    def scan_docker(self,
                    product_name: str = None,
                    product_token: str = None,
                    docker_images: list = None,
                    offline: bool = False,
                    comment: str = None,
                    include: list = None) -> tuple:
        target = self.get_target(None, product_token, product_name)
        if not target:
            logger.error("Docker scan mode is set but no product token of name passed")

        logger.debug("Docker scan mode. Only docker image will be scanned")
        local_ua_all_conf = copy.copy(self.ua_conf)
        local_ua_all_conf.docker_scanImages = True
        self.add_scan_comment(key="comment", value=comment, ua_conf=local_ua_all_conf)
        self.ua_conf.disable_runprestep()
        local_ua_all_conf.docker_scanImages = True
        local_ua_all_conf.projectTag = "scan_type:Docker"
        local_ua_all_conf.projectName = "IRRELEVANT"

        if docker_images:
            local_ua_all_conf.docker_includes = docker_images if isinstance(docker_images, (set, list)) else [docker_images]
            logger.debug(f"Docker images to scan: {local_ua_all_conf.docker_includes}")
        if offline is not None:
            local_ua_all_conf.Offline = offline

        if include:
            local_ua_all_conf.set_include_suffices_to_scan(include)

        ret = self._execute_ua(f"-d {self.ua_path} -{target[0]} {target[1]}", local_ua_all_conf)

        return ret

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
        ret = None
        target = self.get_target(project_token, product_token, product_name)
        if target:
            logger.info(f"Uploading offline request to {target[0]} - {target[1]}")
            if isinstance(offline_request, dict):
                file_path = os.path.join(self.ua_path, "update_request_tmp.json")
                with open(file_path, 'w') as fp:
                    fp.write(json.dumps(offline_request))
            else:
                file_path = offline_request

            ret = self._execute_ua(f"-requestFiles \"{file_path}\" -{target[0]} {target[1]}", self.ua_conf)
        else:
            logger.error("No target was found")

        return ret

    def get_local_ua_semver(self) -> str:
        local_semver = self._execute_ua("-v")[1].strip('\r\n')
        logger.debug(f"Local WhiteSource Unified Agent version {local_semver}")

        return local_semver

    def is_latest_ua_semver(self) -> bool:
        return parse_version(self.get_local_ua_semver()) >= parse_version(ws_utilities.get_latest_ua_release_version())

    def _get_ua_output(self, f) -> dict:
        with open(os.path.join(self.ua_path_whitesource, f), 'r') as fp:
            file_content = fp.read()

        return json.loads(file_content)

    def get_ua_scan_output(self) -> dict:
        return self._get_ua_output("update-request.txt")

    def get_policy_rejection_summary(self) -> dict:
        return self._get_ua_output("policyRejectionSummary.json")

    def get_check_policies(self) -> dict:
        return self._get_ua_output("checkPolicies-json.txt")

    def get_scan_project_details(self) -> dict:
        return self._get_ua_output("scanProjectDetails.json")

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

    @classmethod
    def get_target(cls,
                   project_t: str,
                   product_t: str,
                   product_n: str) -> tuple:
        target = None
        if project_t:
            target = ("projectToken", project_t)
        elif product_t:
            target = ("productToken", product_t)
        elif product_n:
            target = ("product", product_n)

        return target
