import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
from datetime import datetime
from functools import lru_cache
from logging import getLogger

import requests

from ws_sdk.ws_constants import *

logger = getLogger(__name__)


@lru_cache()
def get_spdx_license_dict() -> dict:
    try:
        from spdx.config import _licenses
        with open(_licenses, "r", encoding="utf-8") as fp:
            spdx_licenses = json.loads(fp.read())
        logger.debug(f"License List Version: {spdx_licenses['licenseListVersion']}")

        for spdx_el in spdx_licenses['licenses']:
            if spdx_el['isDeprecatedLicenseId']:
                if spdx_el['isDeprecatedLicenseId']:
                    if spdx_el['licenseId'].find("AGPL-1.0") > -1:
                        spdx_el['licenseId'] = "AGPL-1.0-only" if spdx_el['licenseId'] == "AGPL-1.0" else "AGPL-1.0-or-later"
                    elif spdx_el['licenseId'].find("AGPL-3.0") > -1:
                        spdx_el['licenseId'] = "AGPL-3.0-only" if spdx_el['licenseId'] == "AGPL-3.0" else "AGPL-3.0-or-later"
                    elif spdx_el['licenseId'].find("GPL-1.0") > -1:
                        spdx_el['licenseId'] = "GPL-1.0-only" if spdx_el['licenseId'] == "GPL-1.0" else "GPL-1.0-or-later"
                    elif spdx_el['licenseId'].find("GPL-2.0") > -1:
                        spdx_el['licenseId'] = "GPL-2.0-only" if spdx_el['licenseId'] == "GPL-2.0" else "GPL-2.0-or-later"
                    elif spdx_el['licenseId'].find("GPL-3.0") > -1:
                        spdx_el['licenseId'] = "GPL-3.0-only" if spdx_el['licenseId'] == "GPL-3.0" else "GPL-3.0-or-later"
                    elif spdx_el['licenseId'].find("LGPL-1.0") > -1:
                        spdx_el['licenseId'] = "LGPL-1.0-only" if spdx_el['licenseId'] == "LGPL-1.0" else "LGPL-1.0-or-later"
                    elif spdx_el['licenseId'].find("LGPL-2.0") > -1:
                        spdx_el['licenseId'] = "LGPL-2.0-only" if spdx_el['licenseId'] == "LGPL-2.0" else "LGPL-2.0-or-later"
                    elif spdx_el['licenseId'].find("LGPL-2.1") > -1:
                        spdx_el['licenseId'] = "LGPL-2.1-only" if spdx_el['licenseId'] == "LGPL-2.1" else "LGPL-2.1-or-later"
                    elif spdx_el['licenseId'].find("LGPL-3.0") > -1:
                        spdx_el['licenseId'] = "LGPL-3.0-only" if spdx_el['licenseId'] == "LGPL-3.0" else "LGPL-3.0-or-later"
                    elif spdx_el['licenseId'].find("GFDL-1.1") > -1:
                        spdx_el['licenseId'] = "GFDL-1.1-only" if spdx_el['licenseId'] == "GFDL-1.1" else "GFDL-1.1-or-later"
                    elif spdx_el['licenseId'].find("GFDL-1.2") > -1:
                        spdx_el['licenseId'] = "GFDL-1.2-only" if spdx_el['licenseId'] == "GFDL-1.2" else "GFDL-1.2-or-later"
                    elif spdx_el['licenseId'].find("GFDL-1.3") > -1:
                        spdx_el['licenseId'] = "GFDL-1.3-only" if spdx_el['licenseId'] == "GFDL-1.3" else "GFDL-1.3-or-later"

        spdx_lic_dict = convert_dict_list_to_dict(lst=spdx_licenses['licenses'], key_desc='licenseId')

    except ImportError:
        logger.error("Error loading module")
        raise

    return spdx_lic_dict


def is_token(token: str) -> bool:
    return False if token is None or len(token) != 64 else True


def convert_dict_list_to_dict(lst: list,
                              key_desc: str or tuple = "id",
                              should_replace_f: callable = None) -> dict:
    """
    Function to convert list of dictionaries into dictionary of dictionaries according to specified key
    :param lst: List of dictionaries
    :param key_desc: the key or keys (as tuple) description of the returned dictionary (a key can be str or dict)
    :param should_replace_f: function that receives a and b dictionaries and returns true if a should replace b
    :return: dict with key according to key description and the dictionary value
    """

    def create_key(key_desc: str or tuple,
                   dct: dict) -> str or tuple:
        ret = None
        if isinstance(key_desc, str):
            return dct[key_desc]
        elif isinstance(key_desc, tuple):
            ret = []
            for x in key_desc:
                try:
                    if isinstance(x, str) and dct[x]:
                        ret.append(dct[x])
                        logger.debug(f"Key type is a string: {dct[x]}")
                    elif isinstance(x, dict):
                        for key, value in x.items():
                            logger.debug(f"Key type is a dict: {key}")
                            internal_dict = dct.get(key, None)
                            if internal_dict:
                                ret.append(internal_dict.get(value, None))
                except KeyError:
                    logger.error(f"Key: {key_desc} was not found")
                    return None
            logger.debug(f"Key is tuple: {ret}")
            return tuple(ret)
        else:
            logger.error(f"Unsupported key_desc: {type(key_desc)}")
            return None

    ret = {}
    for i in lst:
        curr_key = create_key(key_desc, i)

        insert_key = False
        if ret.get(curr_key) and should_replace_f:
            logger.warning(f"Key {curr_key} exists. Running '{should_replace_f.__name__}'")
            insert_key = should_replace_f(i, ret[curr_key])
        else:
            insert_key = True

        if insert_key:
            ret[curr_key] = i

    return ret


def get_all_req_schemas(ws_conn) -> dict:
    supported_requests = ws_conn._generic_get(get_type="SupportedRequests", token_type="")['supportedRequests']
    req_schema_list = {}
    for req in supported_requests:
        logger.info(f"Calling on {req}")
        req_schema = ws_conn._generic_get(get_type="RequestSchema", token_type="", kv_dict={"request": req})
        req_schema_list[req] = req_schema

    return req_schema_list


def get_lib_metadata_by_name(language: str) -> LibMetaData.LibMetadata:
    """
    Method that Returns matadata on a language
    :type language: language to return metadata on
    :rtype: NamedTuple
    """
    lc_lang = language.lower()
    for lang_metadata in LibMetaData.L_TYPES:
        if lang_metadata.language == lc_lang:
            return lang_metadata
    logger.error("Language is unsupported")

    return None


def get_package_managers_by_language(language: str) -> list:
    lang_md = get_lib_metadata_by_name(language=language)

    return lang_md.package_manager if lang_md else None


def parse_filename_to_gav(file_string: str) -> tuple:
    import re
    suffix = re.search(r'.([a-zA-z]+$)', file_string)
    name = re.search(r'(^[a-zA-Z0-9-]+)(?=-)', file_string)
    version = re.search(r'-((?!.*-).+)(?=\.)', file_string)

    return {"suffix": suffix.group(1) if suffix else None,
            'name': name.group(1) if name else None,
            'version': version.group(1) if version else None}


def get_full_ws_url(url) -> str:
    if url is None or not url:
        url = 'saas'
    if url in ['saas', 'saas-eu', 'app', 'app-eu']:
        url = f"https://{url}.whitesourcesoftware.com"
    if url.endswith(API_URL_SUFFIX):
        url = url.replace(API_URL_SUFFIX, "")

    return url


def call_gh_api(url: str):
    logger.debug(f"Calling url: {url}")
    try:
        res = requests.get(url=url, headers=GH_HEADERS)
    except requests.RequestException:
        logger.exception("Error getting last release")
        res = None

    return res


def parse_ua_conf(filename: str) -> dict:
    """
    Function that parse ua conf (i.e. wss-unified-agent.config) and returns it as a dictionary
    :param filename:
    :return:
    """
    with open(filename, 'r') as ua_conf_f:
        ua_conf_dict = {}
        for line in ua_conf_f:
            splitted_l = line.strip().split("=")
            if len(splitted_l) > 1:
                ua_conf_dict[splitted_l[0]] = splitted_l[1]

    return ua_conf_dict


class WsConfiguration:
    def __init__(self):
        self.sbt_runPreStep = None
        self.r_runPreStep = None
        self.python_runPipenvPreStep = None
        self.python_runPoetryPreStep = None
        self.php_runPreStep = None
        self.paket_runPreStep = None
        self.ocaml_runPreStep = None
        self.nuget_runPreStep = None
        self.npm_runPreStep = None
        self.maven_runPreStep = None
        self.hex_runPreStep = None
        self.cocoapods_runPreStep = None
        self.cargo_runPreStep = None
        self.haskell_runPreStep = None
        self.bower_runPreStep = None
        self.bazel_runPreStep = None
        self.includes = None

    def set_include_suffices_to_scan(self, includes):
        self.includes = includes

    def disable_runprestep(self):
        self.bazel_runPreStep = False
        self.bower_runPreStep = False
        self.haskell_runPreStep = False
        self.cargo_runPreStep = False
        self.cocoapods_runPreStep = False
        self.hex_runPreStep = False
        self.maven_runPreStep = False
        self.npm_runPreStep = False
        self.nuget_runPreStep = False
        self.ocaml_runPreStep = False
        self.paket_runPreStep = False
        self.php_runPreStep = False
        self.python_runPoetryPreStep = False
        self.python_runPipenvPreStep = False
        self.r_runPreStep = False
        self.sbt_runPreStep = False


def convert_ua_conf_f_to_vars(filename: str) -> WsConfiguration:
    """
    Load UA conf file and create a class with all key as variables
    :param filename: file name to load
    :return: Class with all attributes as variables.
    """
    conf = parse_ua_conf(filename)
    ws_configuration = WsConfiguration()
    for k, v in conf.items():
        if k[0] == '#':
            k = k[1:]
            v = ""
        setattr(ws_configuration, k.replace('.', '_'), v)

    return ws_configuration


def generate_conf_ev(ws_configuration: WsConfiguration) -> dict:
    def to_str(t):
        return ",".join(t) if isinstance(t, (set, list)) else str(t)

    """
    Convert WsConfiguration into UA env vars dictionary
    :param ws_configuration:
    :return: dictionary of env vars
    """
    ws_env_vars = {}

    for k, v in ws_configuration.__dict__.items():
        k = f"WS_" + k.upper()
        if not os.environ.get(k):
            if v is not None:
                ws_env_vars.update({k: to_str(v)})
    return {**os.environ, **ws_env_vars}

    # return {**os.environ,
    #         **{f"WS_" + k.upper(): to_str(v) for k, v in ws_configuration.__dict__.items() if v is not None}}


def init_ua(path: str):
    download_ua(path)


def is_java_exists(java_bin: str = JAVA_BIN) -> bool:
    return True if get_java_version(java_bin) else False


def get_java_version(java_bin: str = JAVA_BIN) -> str:
    ret = None
    output = execute_command(command=java_bin, switches="-version")
    if output[1]:
        output_lines = output[1].splitlines()
        ret = re.findall(r'[0-9._]+', output_lines[0])
        if ret:
            ret = ret[0]
            logger.debug(f"Java version: '{ret}'")
        else:
            ret = None
    else:
        logger.error(f"Unable to discover Java version at: '{java_bin}'")

    return ret


def execute_command(command: str,
                    switches: str = None,
                    env: dict = None) -> tuple:
    def split_switches(sw: str) -> list:
        new_l = []
        val = ""
        regex = re.compile(r'^-[a-z].*')
        for s in sw.split():
            if re.match(regex, s):
                if val:
                    new_l.append(val.strip())
                    val = ""
                new_l.append(s)
            else:
                val = val + s + " "

        if val.strip():
            new_l.append(val.strip())

        return new_l

    full_command_l = [command] + switches if isinstance(switches, list) else [command] + split_switches(switches)
    logger.debug(f"Executing command: {full_command_l}")
    ret = (-1, None)
    try:
        if env:
            output = subprocess.run(args=full_command_l, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            output = subprocess.run(args=full_command_l, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ret = (output.returncode, output.stdout.decode("utf-8"))
    except FileNotFoundError:
        logger.error(f"'{command}' not found")
    except PermissionError:
        logger.error(f"Permission denied running: '{command}'")
    except OSError:
        logger.exception(f"Error running command: '{command}'")

    return ret


def is_ua_exists(ua_jar_f_with_path):
    return os.path.exists(ua_jar_f_with_path)


def download_ua(path: str,
                inc_ua_jar_file: bool = True,
                inc_ua_conf_file: bool = False):
    def download_ua_file(f_details: tuple):
        pathlib.Path(path).mkdir(parents=True, exist_ok=True)
        file_p = os.path.join(path, f_details[0])
        if os.path.exists(file_p):
            logger.debug(f"Backing up previous {f_details[0]}")
            shutil.move(file_p, f"{file_p}.bkp")
        logger.debug(f"Downloading WS Unified Agent (version: {get_latest_ua_release_version()}) to {file_p}")
        resp = requests.get(url=f_details[1])
        with open(file_p, 'wb') as f:
            f.write(resp.content)

    if inc_ua_jar_file:
        download_ua_file(UA_JAR_T)

    if inc_ua_conf_file:
        download_ua_file(UA_CONF_T)


def get_latest_ua_release_version() -> str:
    ver = get_latest_ua_release_url()['tag_name']
    logger.debug(f"Latest Unified Agent version: {ver}")

    return ver


def get_latest_ua_release_url() -> dict:
    res = call_gh_api(url=LATEST_UA_URL)
    if res:
        return json.loads(res.text)
    else:
        return {}


def convert_to_time_obj(time: str):
    return datetime.strptime(time, '%Y-%m-%d %H:%M:%S %z')


class PathType(object):
    def __init__(self, checked_type):

        """When running argparse with argument type=dir/file --> check if exists
        Inspired from https://mail.python.org/pipermail/stdlib-sig/2015-July/000990.html
        type: file, dir, symlink, None, or a function returning True for valid paths None: don't care"""

        if checked_type in ('file', 'dir', 'symlink', None):
            self._type = checked_type

    def __call__(self, string):
        e = os.path.exists(string)
        if not e:
            raise logging.error("path does not exist: '%s'" % string)
        if self._type is None:
            pass
        elif self._type == 'file':
            if not os.path.isfile(string):
                raise logging.error("path is not a file: '%s'" % string)
        elif self._type == 'symlink':
            if not os.path.islink(string):
                raise logging.error("path is not a symlink: '%s'" % string)
        elif self._type == 'dir':
            if not os.path.isdir(string):
                raise logging.error("path is not a directory: '%s'" % string)
        elif not self._type(string):
            raise logging.error("path not valid: '%s'" % string)

        return string
