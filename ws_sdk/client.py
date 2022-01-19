import copy
import dataclasses
import json
import logging
import os
from typing import Union

from pkg_resources import parse_version

from ws_sdk import ws_utilities, ws_errors
from ws_sdk._version import __version__, __tool_name__
from ws_sdk.ws_constants import *

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
                 skip_ua_download: bool = False,
                 tool_details: tuple = ("ps-sdk", __version__),
                 **kwargs
                 ):
        if token_type is ORGANIZATION:
            self.ua_path = ua_path
            self.ua_path_whitesource = os.path.join(self.ua_path, "whitesource")
            self.java_temp_dir = ua_path
            self.ua_jar_f_with_path = os.path.join(ua_path, UA_JAR_F_N)
            # UA configuration
            self.ua_conf = ws_utilities.WsConfiguration()
            self.ua_conf.projectPerFolder = False
            self.ua_conf.apiKey = token
            self.ua_conf.userKey = user_key
            self.ws_url = f"{ws_utilities.get_full_ws_url(url)}"
            self.java_bin = java_bin if bool(java_bin) else JAVA_BIN
            self.ua_conf.wss_url = WSClient.get_client_api_url(self.ws_url)
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

            is_ua_exists = ws_utilities.is_ua_exists(self.ua_jar_f_with_path)
            if not is_ua_exists:
                logger.warning(f"White Source Unified Agent does not exist in path: '{self.ua_jar_f_with_path}'")
            if skip_ua_download or (is_ua_exists and self.is_latest_ua_semver()):
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
        os.chdir(self.ua_path)                                                  # CONSIDER PUTTING ON CONSTRUCTOR
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

    class WsDestScope:
        project_type: str = None
        project_val: str = None
        product_type: str = None
        product_val: str = None
        project_per_folder: bool

        def __init__(self,
                     project_t: str = None,
                     project_n: str = None,
                     product_t: str = None,
                     product_n: str = None,
                     project_per_folder: bool = False):

            self.project_per_folder = project_per_folder

            if project_t:
                self.project_type = "projectToken"
                self.project_val = project_t
            elif project_n:
                self.project_type = ScopeTypes.PROJECT
                self.project_val = project_n

            if product_t:
                self.product_type = "productToken"
                self.product_val = product_t
            elif product_n:
                self.product_type = ScopeTypes.PRODUCT
                self.product_val = product_n

        def __repr__(self):
            ret = f"{self.product_type}: '{self.product_val}'"
            if self.project_type:
                ret += f" {self.project_type}: '{self.project_val}'"

            return ret

        def to_execute(self):
            ret = f"-{self.product_type} {self.product_val}"
            if self.project_type:
                ret += f" -{self.project_type} {self.project_val}"
            elif self.project_per_folder:
                ret += f" -{ScopeTypes.PROJECT} IRRELEVANT"

            return ret

        @property
        def scope_is_full(self):
            return (self.project_val or self.project_per_folder) and self.product_val

    @classmethod
    def extract_support_token(cls, out: str) -> str:
        req_tok = None
        for line in out.splitlines():
            if "Support Token:" in line:
                req_tok = line.split()[-1]
                break

        return req_tok

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
        dest_scope = self.WsDestScope(project_token, project_name, product_token, product_name, self.ua_conf.projectPerFolder)

        ret = None
        if not existing_dirs:
            logger.error(f"No valid directories were found in: {scan_dir}")
        elif not dest_scope.scope_is_full:
            logger.error(f"Missing scope details: {dest_scope}")
        elif not dest_scope.product_val:
            logger.error("product_name or product_token must be configured")
        elif existing_dirs:
            logger.info(f"Scanning Dir(s): {existing_dirs} to {dest_scope}")
            local_ua_all_conf = copy.copy(self.ua_conf)
            self.add_scan_comment(key="comment", value=comment, ua_conf=local_ua_all_conf)

            if offline is not None:
                local_ua_all_conf.Offline = offline

            if include:
                local_ua_all_conf.set_include_suffices_to_scan(include)

            ret = self._execute_ua(f"-d {existing_dirs} {dest_scope.to_execute()}", local_ua_all_conf)
            request_token = self.extract_support_token(ret[1])
            ret += (request_token,)
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
        dest_scope = self.WsDestScope(product_t=product_token, product_n=product_name, project_per_folder=True)
        if not dest_scope:
            logger.error("Docker scan mode is set but no product token of name passed")

        logger.debug("Docker scan mode. Only docker image will be scanned")
        local_ua_all_conf = copy.copy(self.ua_conf)
        local_ua_all_conf.docker_scanImages = True
        self.add_scan_comment(key="comment", value=comment, ua_conf=local_ua_all_conf)
        self.ua_conf.disable_runprestep()
        local_ua_all_conf.docker_scanImages = True
        local_ua_all_conf.projectTag = "scan_type:Docker"

        if docker_images:
            local_ua_all_conf.docker_includes = docker_images if isinstance(docker_images, (set, list)) else [docker_images]
            logger.debug(f"Docker images to scan: {local_ua_all_conf.docker_includes}")
        if offline is not None:
            local_ua_all_conf.Offline = offline

        if include:
            local_ua_all_conf.set_include_suffices_to_scan(include)

        ret = self._execute_ua(f"-d {self.ua_path} {dest_scope.to_execute()}", local_ua_all_conf)
        request_token = self.extract_support_token(ret[1])

        return ret + (request_token,)

    def upload_offline_request(self,
                               offline_request: Union[dict, str],
                               project_token: str = None,
                               project_name: str = None,
                               product_token: str = None,
                               product_name: str = None):
        """
        Method to upload an offline request to WS
        :param offline_request: can accept full path to update file of dict
        :param project_token: target project token
        :param project_name:  target project name
        :param product_token: target product token
        :param product_name: target project name
        """
        ret = None
        dest_scope = self.WsDestScope(project_token, project_name, product_token, product_name)
        if dest_scope.scope_is_full:
            logger.info(f"Uploading offline request to {dest_scope}")
            if isinstance(offline_request, dict):
                file_path = os.path.join(self.ua_path, "update_request_tmp.json")
                with open(file_path, 'w') as fp:
                    fp.write(json.dumps(offline_request))
            else:
                file_path = offline_request

            ret = self._execute_ua(f"-requestFiles \"{file_path}\" {dest_scope.to_execute()}", self.ua_conf)
        else:
            logger.error(f"Invalid target configuration: {dest_scope}")

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

