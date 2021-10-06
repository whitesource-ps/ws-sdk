import json
import logging
from copy import copy
from datetime import datetime, timedelta
from secrets import compare_digest
from typing import Union

from ws_sdk import ws_utilities, ws_errors
import requests
import requests_cache

from ws_sdk.ws_constants import *


def check_permission(permissions: list):                       # Decorator to enforce WS scope token types
    def decorator(function):
        def wrapper(*args, **kwargs):
            def __get_token_type__():                           # Internal method to get token_type from args or kwargs
                token_type = kwargs.get('token_type')
                if token_type is None:
                    try:
                        token_type = args[0].token_type
                    except IndexError:
                        logging.exception("Unable to discover token type")
                        raise ws_errors.WsSdkServerTokenTypeError
                return token_type

            if __get_token_type__() in permissions:
                return function.__call__(*args, **kwargs)
            else:
                logging.error(f"Token Type: {args[0].token_type} is unsupported to execute: {function.__name__}")
        return wrapper
    return decorator


def report_metadata(**kwargs_metadata):
    def decorator(function):
        def wrapper(*args, **kwargs):
            if ReportsData.REPORT_BIN_TYPE in args and kwargs_metadata.get(ReportsData.REPORT_BIN_TYPE):
                logging.debug(f"Accessing report metadata: {ReportsData.REPORT_BIN_TYPE}")
                return kwargs_metadata[ReportsData.REPORT_BIN_TYPE]
            else:
                return function.__call__(*args, **kwargs)
        return wrapper
    return decorator


class WS:
    def __init__(self,
                 user_key: str,
                 token: str,
                 url: str = None,
                 token_type: str = ORGANIZATION,
                 timeout: int = CONN_TIMEOUT,
                 resp_format: str = "json",
                 tool_details: tuple = ("ps-sdk", "0")
                 ):
        """WhiteSource Python SDK
        :api_url: URL for the API to access (e.g. saas.whitesourcesoftware.com)
        :user_key: User Key to use
        :token: Token of scope
        :token_type: Scope Type (organization, product, project)
        :tool_details Tool name and version to include in Body and Header of API requests
        """
        self.user_key = user_key
        self.token = token
        self.token_type = token_type
        self.timeout = timeout
        self.resp_format = resp_format
        self.session = requests_cache.CachedSession(cache_name=self.__class__.__name__,
                                                    expire_after=timedelta(seconds=CACHE_TIME),
                                                    allowable_methods=['GET', 'POST'],
                                                    backend='memory')
        self.api_url = ws_utilities.get_full_ws_url(url) + API_URL_SUFFIX
        self.header_tool_details = {"agent": tool_details[0], "agentVersion": tool_details[1]}
        self.headers = {**WS_HEADERS, **self.header_tool_details}

        if not ws_utilities.is_token(self.user_key):
            logging.warning(f"Invalid User Key: {self.user_key}")

    def set_token_in_body(self,
                          token: str = None) -> (str, dict):
        """
        Determines the token, its type and add into to the request body
        :param token:
        :return: tuple of token_type as string and kv_dict - dictionary
        :rtype: tuple
        """
        kv_dict = {}
        if token is None:
            token_type = self.token_type
            kv_dict[TOKEN_TYPES_MAPPING[token_type]] = self.token
        else:
            token_type = self.get_scope_type_by_token(token)
            kv_dict[TOKEN_TYPES_MAPPING[token_type]] = token
            logging.debug(f"Token: {token} is a {token_type}")

        return token_type, kv_dict

    def call_ws_api(self,
                    request_type: str,
                    kv_dict: dict = None) -> dict:
        def __create_body(api_call: str,
                          kv_d: dict = None) -> tuple:
            ret_dict = {
                        "requestType": api_call,
                        "userKey": self.user_key,
                        "agentInfo": self.header_tool_details
                        }
            if isinstance(kv_d, dict):
                for ent in kv_d:
                    ret_dict[ent] = kv_d[ent]

            toks = [k for k in ret_dict.keys() if 'Token' in k]  # If scope token already configured
            if toks:
                tok = toks[0]
            else:
                ret_dict[TOKEN_TYPES_MAPPING[self.token_type]] = self.token
                tok = TOKEN_TYPES_MAPPING[self.token_type]

            return tok, ret_dict

        def __handle_ws_server_errors(error):
            """
            2007 - User is not in Organization
            2008 - Group does not exist
            2015 - Inactive org
            3010 - Missing fields: user
            4000 - Unexpected error
            5001 - User is not allowed to perform this action
            :param error:
            """
            error_dict = json.loads(error)
            if error_dict['errorCode'] == 2015:
                raise ws_errors.WsSdkServerInactiveOrg(body[token])
            elif error_dict['errorCode'] == 5001:
                raise ws_errors.WsSdkServerInsufficientPermissions(body[token])
            else:
                raise ws_errors.WsSdkServerGenericError(body[token], error)

        token, body = __create_body(request_type, kv_dict)
        logging.debug(f"Calling: {self.api_url} with requestType: {request_type}")
        self.session.expire_after = timedelta(seconds=CACHE_TIME)

        try:
            resp = self.session.post(self.api_url, data=json.dumps(body), headers=self.headers, timeout=self.timeout)
        except requests.RequestException:
            logging.exception(f"Received Error on {body[token[-1]]}")
            raise

        if not request_type.startswith("get"):
            logging.debug("Expiring request cache")
            self.session.expire_after = 0

        if resp.status_code > 299:
            logging.error(f"API {body['requestType']} call on {body[token[-1]]} failed: {resp.text}")
            raise requests.exceptions.RequestException
        elif "errorCode" in resp.text:
            logging.debug(f"API returned errorCode {body['requestType']} call on {body[token]} message: {resp.text}")
            __handle_ws_server_errors(resp.text)
        else:
            logging.debug(f"API {body['requestType']} call on {token} {body[token]} succeeded")

        try:
            ret = json.loads(resp.text)
        except json.JSONDecodeError:
            logging.debug("Response is not a JSON object")
            if resp.encoding is None:
                logging.debug("Response is binary")
                ret = resp.content
            else:
                logging.debug(f"Response encoding: {resp.encoding}")
                ret = resp.text

        return ret

    def __generic_get__(self,
                        get_type: str,
                        token_type: str = None,
                        kv_dict: dict = None) -> [list, dict, bytes]:
        """
        This function completes the API type and calls.
        :param get_type:
        :param token_type:
        :param kv_dict:
        :return: can be list, dict, none or bytes (pdf, xlsx...)
        :rtype: list or dict or bytes
        """
        if token_type is None:
            token_type = self.token_type

        return self.call_ws_api(f"get{token_type.capitalize()}{get_type}", kv_dict)

    def __generic_set__(self,
                        set_type: str,
                        token_type: str = None,
                        kv_dict: dict = None) -> [list, dict, bytes]:
        """
        This function completes the API type and calls.
        :param set_type:
        :param token_type:
        :param kv_dict:
        :return: can be list, dict, none or bytes (pdf, xlsx...)
        :rtype: list or dict or bytes
        """
        if token_type is None:
            token_type = self.token_type

        return self.call_ws_api(f"set{token_type.capitalize()}{set_type}", kv_dict)

    # Covers O/P/P + byType + report
    @report_metadata(report_bin_type="xlsx")
    def get_alerts(self,
                   token: str = None,
                   alert_type: str = None,
                   from_date: datetime = None,
                   to_date: datetime = None,
                   project_tag: bool = False,
                   tag: dict = {},
                   ignored: bool = False,
                   resolved: bool = False,
                   report: bool = False) -> Union[list, bytes, None]:
        """
        Retrieves open alerts of all types
        :param token: The token that the request will be created on
        :param alert_type: Allows filtering alerts by a single type from ALERT_TYPES
        :param from_date: Allows filtering of alerts by start date. Works together with to_date
        :param to_date: Allows filtering of alerts by end date. Works together with from_date
        :param project_tag: should filter by project tags
        :param tag: dict of Key:Value of the tag. Allowed only 1 pair
        :param ignored: Should output include ignored reports
        :param resolved: Should output include resolved reports
        :param report: Create xlsx report type
        :return: list with alerts or xlsx if report is True
        :rtype: list or bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if alert_type in AlertTypes.ALERT_TYPES:
            kv_dict["alertType"] = alert_type
        elif alert_type:
            logging.error(f"Alert: {alert_type} does not exist")
            return None

        if isinstance(from_date, datetime):
            kv_dict["fromDate"] = from_date.strftime(DATE_FORMAT)
        if isinstance(to_date, datetime):
            kv_dict["toDate"] = to_date.strftime(DATE_FORMAT)

        ret = None
        if resolved and report:
            logging.debug("Running Resolved Alerts Report")
            ret = self.__generic_get__(get_type='ResolvedAlertsReport', token_type=token_type, kv_dict=kv_dict)
        elif ignored and report:
            logging.debug("Running ignored Alerts Report")
            ret = self.__generic_get__(get_type='SecurityAlertsByVulnerabilityReport', token_type=token_type, kv_dict=kv_dict)
        elif resolved:
            logging.error("Resolved Alerts is only available in xlsx format(set report=True)")
        elif ignored:
            logging.debug("Running ignored Alerts")
            ret = self.__generic_get__(get_type='IgnoredAlerts', token_type=token_type, kv_dict=kv_dict)
        elif report:
            logging.debug("Running Alerts Report")
            kv_dict["format"] = "xlsx"
            ret = self.__generic_get__(get_type='AlertsReport', token_type=token_type, kv_dict=kv_dict)
        elif project_tag:
            if token_type != ORGANIZATION:
                logging.error("Getting project alerts tag is only supported with organization token")
            elif len(tag) == 1:
                logging.debug("Running Alerts by project tag")
                ret = self.__generic_get__(get_type='AlertsByProjectTag', token_type=token_type, kv_dict=kv_dict)
            else:
                logging.error("Alerts tag is not set correctly")
        elif kv_dict.get('alertType') is not None:
            logging.debug("Running Alerts By Type")
            ret = self.__generic_get__(get_type='AlertsByType', token_type=token_type, kv_dict=kv_dict)
        else:
            logging.debug("Running Alerts")
            ret = self.__generic_get__(get_type='Alerts', token_type=token_type, kv_dict=kv_dict)

        return ret.get('alerts') if isinstance(ret, dict) else ret

    @report_metadata(report_bin_type="xlsx")
    def get_ignored_alerts(self,
                           token: str = None,
                           report: bool = False) -> Union[list, bytes]:
        return self.get_alerts(token=token, report=report, ignored=True)

    @report_metadata(report_bin_type="xlsx")
    def get_resolved_alerts(self,
                            token: str = None,
                            report: bool = False) -> Union[list, bytes]:
        return self.get_alerts(token=token, report=report, resolved=True)

    @report_metadata(report_bin_type="xlsx")
    def get_inventory(self,
                      token: str = None,
                      include_in_house_data: bool = True,
                      with_dependencies: bool = False,
                      report: bool = False) -> Union[list, bytes]:
        """
        :param with_dependencies: Include library dependency (Project Hierarchy)
        :param token: The token that the request will be created on
        :param include_in_house_data:
        :param report: Get data in binary form
        :return: list or xlsx if report is True
        :rtype: list or bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        report_name = 'Inventory'

        if token_type == PROJECT and not include_in_house_data:
            kv_dict["includeInHouseData"] = include_in_house_data
            logging.debug(f"Running {token_type} {report_name}")
            ret = self.__generic_get__('Inventory', token_type=token_type, kv_dict=kv_dict)
        elif token_type == PROJECT and with_dependencies:
            logging.debug(f"Running {token_type} Hierarchy")
            ret = self.__generic_get__(get_type="Hierarchy", token_type=token_type, kv_dict=kv_dict)
        else:
            kv_dict["format"] = "xlsx" if report else "json"
            logging.debug(f"Running {token_type} {report_name} Report")
            ret = self.__generic_get__(get_type="InventoryReport", token_type=token_type, kv_dict=kv_dict)

        return ret['libraries'] if isinstance(ret, dict) else ret

    def get_scope_type_by_token(self,
                                token: str) -> str:
        return self.get_scope_by_token(token)['type']

    def get_scope_name_by_token(self,
                                token: str) -> str:
        return self.get_scope_by_token(token)['name']

    def get_scope_by_token(self,
                           token: str) -> dict:
        """
        Method to return the scope of a token, if not found, raise exception.
        :param token: the searched token
        :return: dictionary of scope
        :rtype: dict
        """
        ret = self.get_scopes(token=token)

        if ret:
            return ret[0]
        else:
            raise ws_errors.WsSdkServerMissingTokenError(token, self.token_type)

    def get_scopes(self,
                   name: str = None,
                   token: str = None,
                   scope_type: str = None,
                   product_token: str = None) -> list:
        """
        :param name: filter returned scopes by name
        :param token: filter by token
        :param scope_type: filter by scope type
        :param product_token: filter projects by product token
        :return: list of scope dictionaries
        :rtype list
        """
        def __enrich_projects__(proj_list: list, prod: dict) -> list:
            for project in proj_list:
                project['type'] = PROJECT
                project[TOKEN_TYPES_MAPPING[PRODUCT]] = prod.get('token')
                project['productName'] = prod.get('name')

            return proj_list

        def __get_projects_from_product__(products: list):
            all_projs = []
            for p in products:
                try:
                    prod_projects = self.__generic_get__(get_type="ProjectVitals",
                                                         kv_dict={TOKEN_TYPES_MAPPING[PRODUCT]: p['token']},
                                                         token_type='product')['projectVitals']
                    all_projs.extend(__enrich_projects__(prod_projects, p))
                except KeyError:
                    logging.debug(f"Product: {p['name']} Token {p['token']} without projects. Skipping")

            return all_projs

        def __create_self_scope__() -> dict:
            return {'type': self.token_type,
                    'token': self.token,
                    'name': self.get_name()}
        # toDo better handling while using product_token when scope type is org
        scopes = []
        if self.token_type == PRODUCT:
            product = __create_self_scope__()
            projects = self.__generic_get__(get_type="ProjectVitals")['projectVitals']
            scopes = __enrich_projects__(projects, product)
            scopes.append(product)
        elif self.token_type == ORGANIZATION:
            all_products = self.__generic_get__(get_type="ProductVitals")['productVitals']
            prod_token_exists = False

            for product in all_products:
                product['type'] = PRODUCT
                product['org_token'] = self.token

                if product['token'] == token:
                    logging.debug(f"Found searched token: {token}")
                    scopes.append(product)
                    return scopes                                              # TODO FIX THIS
                elif product['token'] == product_token:
                    logging.debug(f"Found searched productToken: {token}")
                    prod_token_exists = True
                    break

            if not prod_token_exists and product_token is not None:
                raise ws_errors.WsSdkServerMissingTokenError(product_token, self.token_type)

            if scope_type not in [ORGANIZATION, PRODUCT]:
                if product_token:
                    all_products = [prod for prod in all_products if prod['token'] == product_token]
                all_projects = __get_projects_from_product__(all_products)
                scopes.extend(all_projects)
            if scope_type not in [ORGANIZATION, PROJECT]:
                scopes.extend(all_products)
            if scope_type in [ORGANIZATION, None]:
                scopes.append(self.get_organization_details())
        elif self.token_type == GLOBAL:
            organizations = self.__generic_get__(get_type="AllOrganizations", token_type="")['organizations']
            for org in organizations:
                org['global_token'] = self.token
                org['token'] = org['orgToken']
                org['type'] = ORGANIZATION

            scopes = []
            if scope_type in [PROJECT, PRODUCT]:
                for org in organizations:
                    temp_conn = WS(url=self.url,
                                   user_key=self.user_key,
                                   token=org['orgToken'],
                                   token_type=ORGANIZATION)
                    try:
                        scopes.extend(temp_conn.get_scopes(scope_type=scope_type))
                        org['active'] = True
                    except ws_errors.WsSdkServerInactiveOrg as e:
                        logging.warning(e.message)
                        org['active'] = False
            else:
                scopes.extend(organizations)
                scopes.append(__create_self_scope__())
        else:                                                               # self.token_type == PROJECT
            scopes.append(__create_self_scope__())
        # Filter scopes
        if token:
            scopes = [scope for scope in scopes if compare_digest(scope['token'], token)]

        if name:
            scopes = [scope for scope in scopes if scope['name'] == name]
        if scope_type is not None:                                              # 2nd filter because scopes may contain full scope due to caching
            scopes = [scope for scope in scopes if scope['type'] == scope_type]
        if product_token:
            scopes = [scope for scope in scopes if scope.get(TOKEN_TYPES_MAPPING[PRODUCT]) == product_token]

        logging.info(f"{len(scopes)} results were found")       # Check that MissingTokenError is not in use in other repos

        return scopes

    @check_permission(permissions=[ORGANIZATION])
    def get_organization_details(self) -> dict:
        org_details = self.__generic_get__(get_type='Details')
        org_details['name'] = org_details.get('orgName')
        org_details['token'] = org_details.get('orgToken')
        org_details['type'] = ORGANIZATION

        return org_details

    def get_name(self) -> str:
        """
        Method to retun self name of token configured in SDK
        :return: name of configured in SDK
        :rtype: str
        """
        if self.token_type == ORGANIZATION:
            return self.get_organization_details()['orgName']
        elif self.token_type == GLOBAL:
            return "TBD"
        else:
            return self.get_tags()[0]['name']

    def get_scopes_from_name(self, name) -> list:
        """
        :param name:
        :return:
        """
        return self.get_scopes(name=name)

    def get_tokens_from_name(self,
                             scope_name: str) -> list:
        scopes = self.get_scopes_from_name(scope_name)
        ret = []
        for scope in scopes:
            ret.append(scope['token'])

        return ret

    @check_permission(permissions=[GLOBAL])
    def get_organizations(self,
                          name: str = None,
                          token: str = None,
                          active: bool = None) -> list:
        """
        Get all organizations under global organization
        :param name: filter by name
        :param token: filter by token
        :param active: whether to return active only
        :return: list of organization
        :rtype: list
        """
        ret = self.get_scopes(name=name, token=token, scope_type=ORGANIZATION)

        if active:
            ret = [org for org in ret if org.get('active') == active]

        return ret

    @check_permission(permissions=[ORGANIZATION])
    def get_products(self,
                     name: str = None) -> list:

        return self.get_scopes(name=name, scope_type=PRODUCT)

    def get_projects(self,
                     name: str = None,
                     product_token: str = None) -> list:
        """
        :param name: filter returned scopes by name
        :param product_token: if stated retrieves projects of specific product. If left blank retrieves all the projects in the org
        :return: list
        :rtype list
        """
        return self.get_scopes(name=name, scope_type=PROJECT, product_token=product_token)

    @report_metadata(report_bin_type="xlsx")
    def get_vulnerability(self,
                          status: str = None,  # "Active", "Ignored", "Resolved"
                          container: bool = False,
                          cluster: bool = False,
                          report: bool = False,
                          token: str = None) -> Union[list, bytes]:
        report_name = "Vulnerability Report"
        """
        Retrieves scope vulnerabilities. Default is "Open" If status not not set.   
        :param status: str Alert status: "Active", "Ignored", "Resolved"
        :param container:
        :param cluster:
        :param report:
        :param token: The token that the request will be created on
        :return: list or xlsx if report is True
        :rtype: list or bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if not report:
            kv_dict["format"] = self.resp_format
        if status in AlertStatus.ALERT_STATUSES:
            kv_dict['status'] = status
        ret = None

        if container:
            if token_type == ORGANIZATION:
                logging.debug(f"Running Container {report_name}")
                ret = self.__generic_get__(get_type='ContainerVulnerabilityReportRequest', token_type=token_type, kv_dict=kv_dict)
            else:
                logging.error(f"Container {report_name} is unsupported on {token_type}")
        elif cluster:
            if token_type == PRODUCT:
                logging.debug(f"Running Cluster {report_name}")
                ret = self.__generic_get__(get_type='ClusterVulnerabilityReportRequest', token_type="", kv_dict=kv_dict)
            else:
                logging.error(f"Cluster {report_name} is unsupported on {token_type}")
        else:
            logging.debug(f"Running {report_name}")
            ret = self.__generic_get__(get_type='VulnerabilityReport', token_type=token_type, kv_dict=kv_dict)

        return ret['vulnerabilities'] if isinstance(ret, dict) else ret

    @report_metadata(report_bin_type="xlsx")
    def get_container_vulnerability(self,
                                    report: bool = False,
                                    token: str = None) -> bytes:
        return self.get_vulnerability(container=True, report=report, token=token)

    def get_vulnerabilities_per_lib(self,
                                    token: str = None) -> list:
        def __get_highest_severity__(comp_severity, severity):
            sev_dict = {"high": 3, "medium": 2, "low": 1, "none": 0}

            return comp_severity if sev_dict[comp_severity] > sev_dict[severity] else severity

        vuls = self.get_vulnerability(token=token)
        logging.debug(f"Found {len(vuls)} Vulnerabilities")
        libs_vul = {}

        for vul in vuls:
            lib = vul['library']
            key_uuid = lib['keyUuid']
            if not libs_vul.get(key_uuid):
                lib_dict = {}
                for key in lib.keys():
                    lib_dict[key] = lib[key]
                lib_dict['vulnerabilities'] = set()
                lib_dict['severity'] = "none"
                libs_vul[key_uuid] = lib_dict
            libs_vul[key_uuid]['vulnerabilities'].add(vul['name'])
            curr_severity = vul['severity']
            libs_vul[key_uuid]['severity'] = __get_highest_severity__(curr_severity, libs_vul[key_uuid]['severity'])
            libs_vul[key_uuid]['lib_url'] = f"{self.url}/Wss/WSS.html#!libraryDetails;uuid={key_uuid};{TOKEN_TYPES_MAPPING[self.token_type]}={self.token}"
            libs_vul[key_uuid]['project'] = vul['project']
            libs_vul[key_uuid]['product'] = vul['product']
        logging.debug(f"Found {len(libs_vul)} libraries with vulnerabilities")

        return list(libs_vul.values())

    @check_permission(permissions=[ORGANIZATION])
    def get_change_log(self,
                       start_date: datetime = None) -> list:
        report_name = "Change Log Report"
        if start_date is None:
            kv_dict = None
        else:
            kv_dict = {'startDateTime': start_date.strftime("%Y-%m-%d %H:%M:%S")}
        logging.debug(f"Running {report_name}")

        return self.__generic_get__(get_type="ChangesReport", token_type="", kv_dict=kv_dict)['changes']

    def get_licenses(self,
                     token: str = None,
                     exclude_project_occurrences: bool = False,
                     histogram: bool = False,
                     full_spdx: bool = False) -> list:
        """
        Run Licenses Report
        :param token: The token to generate report on
        :param exclude_project_occurrences: whether to excluded occurrences
        :param histogram: Return number of license occurrences.
        :param full_spdx: Whether to enrich SPDX data with full license name and URL (requires spdx-tools package)
        :return: list
        """
        def __get_spdx__() -> dict:
            logging.debug("Enriching license data with SDPX information")
            licenses_dict = None
            try:
                from spdx.config import _licenses
                with open(_licenses, "r") as fp:
                    spdx_licenses = json.loads(fp.read())
                logging.debug(f"License List Version: {spdx_licenses['licenseListVersion']}")
                licenses_dict = ws_utilities.convert_dict_list_to_dict(lst=spdx_licenses['licenses'], key_desc='licenseId')
            except ImportError:
                logging.error("Error loading module")
                raise

            return licenses_dict

        def __fix_spdx_license__(lic: dict) -> None:
            if not lic.get('spdxName'):
                if lic.get('name') == "Public Domain":
                    lic['spdxName'] = "CC-PDDC"
                elif lic.get('name') == "AGPL":
                    lic['spdxName'] = "AGPL-1.0"
                elif lic.get('name') == "BSD Zero":
                    lic['spdxName'] = "0BSD"

                if lic.get('spdxName'):
                    logging.info(f"Fixed spdxName of {lic['name']} to {lic['spdxName']}")
                else:
                    logging.warning(f"Unable to fix spdxName of {lic['name']}")

        def __enrich_lib__(library: dict, spdx: dict):
            for lic in library.get('licenses'):
                __fix_spdx_license__(lic)                                        # Manually fixing this license
                try:
                    lic['spdx_license_dict'] = spdx[lic['spdxName']]
                    logging.debug(f"Found license: {lic['spdx_license_dict']['licenseId']}")
                except KeyError:
                    logging.warning(f"License with identifier: {lic['name']} was not found")

        report_name = 'licenses'
        token_type, kv_dict = self.set_token_in_body(token)
        if histogram:
            logging.debug(f"Running {token_type} {report_name} Histogram")
            ret = self.__generic_get__(get_type='LicenseHistogram', token_type=token_type, kv_dict=kv_dict)['licenseHistogram']
        else:
            logging.debug(f"Running {token_type} {report_name}")
            kv_dict['excludeProjectOccurrences'] = exclude_project_occurrences
            ret = self.__generic_get__(get_type='Licenses', token_type=token_type, kv_dict=kv_dict)['libraries']

            if full_spdx:
                spdx_dict = __get_spdx__()
                for lib in ret:
                    __enrich_lib__(lib, spdx_dict)

        return ret

    @report_metadata(report_bin_type="xlsx")
    def get_source_files(self,
                         token: str = None,
                         report: bool = False) -> Union[list, bytes]:
        report_name = 'Source File Inventory Report'
        token_type, kv_dict = self.set_token_in_body(token)
        if report:
            kv_dict["format"] = "xlsx"
            logging.debug(f"Running {token_type} {report_name}")
        else:
            kv_dict["format"] = "json"
            logging.debug(f"Running {token_type} Inventory")
        ret = self.__generic_get__(get_type='SourceFileInventoryReport', token_type=token_type, kv_dict=kv_dict)

        return ret['sourceFiles'] if isinstance(ret, dict) else ret

    @report_metadata(report_bin_type="xlsx")
    def get_source_file_inventory(self,
                                  report: bool = True,
                                  token: str = None) -> bytes:
        return self.get_source_files(token=token, report=report)

    @report_metadata(report_bin_type="xlsx")
    def get_in_house_libraries(self,
                               report: bool = False,
                               token: str = None) -> Union[list, bytes]:
        """
        :param report: get output as xlsx if True
        :param token: The token that the request will be created on
        :return: list or bytes(xlsx)
        :rtype: list or bytes
        """
        report_name = 'In-House Libraries'
        token_type, kv_dict = self.set_token_in_body(token)
        if report:
            logging.debug(f"Running {token_type} {report_name} Report")
            ret = self.__generic_get__(get_type='InHouseReport', token_type=token_type, kv_dict=kv_dict)
        else:
            logging.debug(f"Running {token_type} {report_name}")
            ret = self.__generic_get__(get_type='InHouseLibraries', token_type=token_type, kv_dict=kv_dict)['libraries']

        return ret['sourceFiles'] if isinstance(ret, dict) else ret

    @report_metadata(report_bin_type="xlsx")
    def get_in_house(self,
                     report: bool = True,
                     token: str = None) -> bytes:
        return self.get_in_house_libraries(report=report, token=token)

    @check_permission(permissions=[ORGANIZATION])
    def get_users(self,
                  name: str = None,
                  email: str = None) -> list:
        """
        Get organization users
        :param name: filter list by user name
        :return: list of users
        """
        logging.debug(f"Getting organization users")
        ret = self.__generic_get__(get_type='AllUsers', token_type="")['users']

        if name:
            ret = [user for user in ret if user.get('name') == name]
        if email:
            ret = [user for user in ret if user.get('email') == email]

        return ret

    @check_permission(permissions=[ORGANIZATION])
    def get_groups(self,
                   name: str = None,
                   user_name: str = None,
                   user_email: str = None) -> list:
        """
        Get organization groups
        :param name: Filter groups by group name
        :param user_name: return groups that contains user name
        :param user_email: return groups that contains user name
        :return: list of groups
        :rtype: list
        """
        def __filter_by_user_detail__(detail: str,
                                      detail_value: str,
                                      groups: list) -> list:
            ret_groups = []
            for group in groups:
                for user in group['users']:
                    if detail_value == user[detail]:
                        ret_groups.append(group)

            return ret_groups

        """
        Get organization Groups
        :param name: filter list by group name
        :param user_name: only returns groups that user assigned to them
        :param user_email: only returns groups that user email assigned to them
        :return: list of groups
        :return: list of groups
        :rtype: list
        """
        logging.debug("Getting Organization groups")
        ret = self.__generic_get__(get_type="AllGroups", token_type="")['groups']
        if name:
            ret = [group for group in ret if group.get('name') == name]
        if user_name:
            ret = __filter_by_user_detail__(detail='name', detail_value=user_name, groups=ret)
        if user_email:
            ret = __filter_by_user_detail__(detail='email', detail_value=user_email, groups=ret)

        return ret

    def get_user_group_assignments(self,            # TODO MERGE WITH GET_USERS and GET_GROUPS
                                   token: str = None,
                                   role_type: str = None,
                                   entity_type: str = None) -> list:
        """
        Get users and Groups assignments
        :param token: scope token to retrieve assignments
        :param role_type: accepted roles: DEFAULT_APPROVER, PRODUCT_INTEGRATOR, ADMIN
        :param entity_type: whether to filter user or group assignments.
        :return: flat list of of entities (users and groups) with their role, type and token
        :rtype list
        """
        report_name = "Assignment"
        token_type, kv_dict = self.set_token_in_body(token)
        ret_assignments = []
        if token_type == PROJECT:
            logging.error(f"{report_name} is unsupported on project")
        else:
            logging.debug(f"Running {token_type} Assignment")
            assignments = self.__generic_get__(get_type='Assignments', token_type=token_type, kv_dict=kv_dict)
            ret_assignments = []
            for ent in ENTITY_TYPES.items():
                role_types = assignments.get(ent[1])
                if role_types:
                    for r_t in role_types.items():
                        for e in r_t[1]:
                            e['scope_token'] = token
                            e['role_type'] = r_t[0]
                            e['ent_type'] = ent[0][:-1]
                            ret_assignments.append(e)
                else:
                    logging.debug(f"No roles were found under: {ent[1]}")

            if entity_type in ENTITY_TYPES.keys():
                logging.debug(f"Filtering assignments by entity type: {entity_type}")
                ret_assignments = [asc for asc in ret_assignments if asc['ent_type'] == entity_type[:-1]]

            if role_type in RoleTypes.ROLE_TYPES:
                logging.debug(f"Filtering assignments by role type: {role_type}")
                ret_assignments = [asc for asc in ret_assignments if asc['role_type'] == role_type]

        return ret_assignments

    @report_metadata(report_bin_type="pdf")
    def get_risk(self,
                 token: str = None,
                 report: bool = True) -> bytes:
        """API for WhiteSource
        :token: Token of scope
        :token_type: Scope Type (organization, product, project)
        :return bytes (pdf)
        :rtype: bytes
        """
        report_name = "Risk Report"
        token_type, kv_dict = self.set_token_in_body(token)
        if not report:
            logging.error(f"Report {report_name} is supported in pdf format. (set report=True)")
        elif token_type == PROJECT:
            logging.error(f"{report_name} is unsupported on project")
        else:
            logging.debug(f"Running {report_name} on {token_type}")
            return self.__generic_get__(get_type='RiskReport', token_type=token_type, kv_dict=kv_dict)

    @report_metadata(report_bin_type="xlsx")
    def get_library_location(self,
                             token: str = None,
                             report: bool = False) -> Union[list, bytes]:
        report_name = "Library Location"
        """
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if report and token_type == PROJECT:
            logging.error(f"{report_name} report is unsupported on {token_type}")
        elif report:
            logging.debug(f"Running {report_name} report on {token_type}")
            ret = self.__generic_get__(get_type='LibraryLocationReport', token_type=token_type, kv_dict=kv_dict)
        elif not report and token_type == ORGANIZATION:
            logging.error(f"{report_name} is unsupported on {token_type}")
            ret = None
        else:
            logging.debug(f"Running {report_name} on {token_type}")
            ret = self.__generic_get__(get_type='LibraryLocations', token_type=token_type, kv_dict=kv_dict)

        return ret['libraryLocations'] if isinstance(ret, dict) else ret

    @report_metadata(report_bin_type="xlsx")
    def get_license_compatibility(self,
                                  token: str = None,
                                  report: bool = False) -> bytes:
        report_name = "License Compatibility Report"
        """
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if not report:
            logging.error(f"{report_name} is supported in xlsx format. (set report=True)")
        elif token_type == ORGANIZATION:
            logging.error(f"{report_name} is unsupported on organization level")
        else:
            logging.debug(f"Running {report_name} on {token_type}")
            return self.__generic_get__(get_type='LicenseCompatibilityReport', token_type=token_type, kv_dict=kv_dict)

    @report_metadata(report_bin_type="xlsx")
    def get_due_diligence(self,
                          token: str = None,
                          report: bool = False) -> Union[list, bytes]:
        report_name = "Due Diligence Report"
        f""" {report_name}
        :param token: The token that the request will be created on str
        :param token: The token that the request will be created on bool - Should 
        :return: list or bytes (xlsx)
        :rtype list or bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if not report:
            kv_dict["format"] = "json"
        logging.debug(f"Running {report_name} on {token_type}")
        ret = self.__generic_get__(get_type='DueDiligenceReport', token_type=token_type, kv_dict=kv_dict)

        return ret['licenses'] if isinstance(ret, dict) else ret

    @report_metadata(report_bin_type="xlsx")
    def get_attributes(self,
                       token: str = None) -> bytes:
        """
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        report_name = "Attributes Report"
        token_type, kv_dict = self.set_token_in_body(token)
        if token_type == PROJECT:
            logging.error(f"{report_name} is unsupported on project")
        else:
            logging.debug(f"Running {token_type} {report_name}")
            return self.__generic_get__(get_type='AttributesReport', token_type=token_type, kv_dict=kv_dict)

    @report_metadata(report_bin_type=["html", 'txt'])
    def get_attribution(self,
                        reporting_aggregation_mode: str,
                        token: str,
                        report_header: str = "Attribution Report",
                        report_title: str = None,
                        report_footer: str = None,
                        reporting_scope: str = None,
                        missing_license_display_option: str = "BLANK",
                        export_format: str = "JSON",
                        license_reference_text_placement: str = "LICENSE_SECTION",
                        custom_attribute: str = None,
                        include_versions: str = True) -> Union[dict, bytes]:
        """
        Method that creates Inventory like response with custom attrbiuted and notice text/reference data
        :param reporting_aggregation_mode:
        :param token:
        :param report_header:
        :param report_title:
        :param report_footer:
        :param reporting_scope:
        :param missing_license_display_option:
        :param export_format:
        :param license_reference_text_placement:
        :param custom_attribute:
        :param include_versions:
        :return:
        """
        report_name = "Attribution Report"
        token_type, kv_dict = self.set_token_in_body(token)
        if token_type == ORGANIZATION:
            logging.error(f"{report_name} is unsupported on organization")
        elif reporting_aggregation_mode not in ['BY_COMPONENT', 'BY_PROJECT']:
            logging.error(f"{report_name} incorrect reporting_aggregation_mode value. Supported: BY_COMPONENT or BY_PROJECT")
        elif missing_license_display_option not in ['BLANK', 'GENERIC_LICENSE']:
            logging.error(f"{report_name} missing_license_display_option value. Supported: BLANK or GENERIC_LICENSE")
        elif export_format not in ['TXT', 'HTML', 'JSON']:
            logging.error(f"{report_name} incorrect export_format value. Supported: TXT, HTML or JSON")
        elif reporting_scope not in [None, 'SUMMARY', 'LICENSES', 'COPYRIGHTS', 'NOTICES', 'PRIMARY_ATTRIBUTES']:
            logging.error(f"{report_name} incorrect reporting scope value. Supported: SUMMARY, LICENSES, COPYRIGHTS, NOTICES or PRIMARY_ATTRIBUTES")
        elif license_reference_text_placement not in ['LICENSE_SECTION', 'APPENDIX_SECTION']:
            logging.error(f"{report_name} incorrect license_reference_text_placement value. Supported:  LICENSE_SECTION or APPENDIX_SECTION  ")
        else:
            kv_dict['reportHeader'] = report_header
            kv_dict['reportTitle'] = report_title
            kv_dict['reportFooter'] = report_footer
            kv_dict['reportingScope'] = reporting_scope
            kv_dict['reportingAggregationMode'] = reporting_aggregation_mode
            kv_dict['missingLicenseDisplayOption'] = missing_license_display_option
            kv_dict['exportFormat'] = export_format
            kv_dict['licenseReferenceTextPlacement'] = license_reference_text_placement
            kv_dict['customAttribute'] = custom_attribute
            kv_dict['includeVersions'] = include_versions
            logging.debug(f"Running {token_type} {report_name}")

            return self.__generic_get__(get_type='AttributionReport', token_type=token_type, kv_dict=kv_dict)

    @report_metadata(report_bin_type="xlsx")
    def get_effective_licenses(self,
                               token: str = None) -> bytes:
        """
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        report_name = 'Effective Licenses Report'
        token_type, kv_dict = self.set_token_in_body(token)
        if token_type == PROJECT:
            logging.error(f"{report_name} is unsupported on project")
        else:
            logging.debug(f"Running {token_type} {report_name}")
            return self.__generic_get__(get_type='EffectiveLicensesReport', token_type=token_type, kv_dict=kv_dict)

    @report_metadata(report_bin_type="xlsx")
    def get_bugs(self,
                 report: bool = True,
                 token: str = None) -> bytes:
        """
        :param report: True to generate document file (currently the only option supported)
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        report_name = 'Bugs Report'
        ret = None
        if report:
            token_type, kv_dict = self.set_token_in_body(token)
            logging.debug(f"Running {token_type} {report_name}")

            ret = self.__generic_get__(get_type='BugsReport', token_type=token_type, kv_dict=kv_dict)
        else:
            logging.error(f"{report_name} is only supported as xls (set report=True")

        return ret

    @report_metadata(report_bin_type="xlsx")
    def get_request_history(self,
                            plugin: bool = False,
                            report: bool = True,
                            token: str = None) -> bytes:
        """
        :param report: True to generate document file (currently the only option supported)
        :param plugin: bool
        :param token: The token that the request will be created on str
        :return: bytes (xlsx)
        :rtype bytes
        """
        report_name = 'Request History Report'
        token_type, kv_dict = self.set_token_in_body(token)
        ret = None
        if not report:
            logging.error(f"{report_name} is only supported as xlsx (set report=True")
        elif plugin and token_type == ORGANIZATION:
            ret = self.__generic_get__(get_type='PluginRequestHistoryReport', token_type=token_type, kv_dict=kv_dict)
        elif plugin:
            logging.error(f"Plugin {report_name} unsupported for {token_type}")
        else:
            logging.debug(f"Running {token_type} {report_name}")
            ret = self.__generic_get__(get_type='RequestHistoryReport', token_type=token_type, kv_dict=kv_dict)

        return ret

    def get_product_of_project(self,
                               token: str) -> dict:
        project_scope = self.get_scope_by_token(token=token)
        if project_scope['type'] == PROJECT:
            return self.get_scope_by_token(token=project_scope[TOKEN_TYPES_MAPPING[PRODUCT]])

    def get_project(self,
                    token: str) -> dict:
        all_projects = self.get_projects()
        for project in all_projects:
            if compare_digest(project['token'], token):
                return project
        logging.error(f"Project with token: {token} was not found")

    def get_tags(self,
                 token: str = None) -> list:
        report_name = "Tags"
        token_type, kv_dict = self.set_token_in_body(token)

        if token and token_type == PROJECT or self.token_type == PROJECT:                              # getProjectTags
            ret = self.__generic_get__(get_type="ProjectTags", token_type="", kv_dict=kv_dict)['projectTags']
        elif token and token_type == PRODUCT or self.token_type == PRODUCT:                            # getProductTags
            ret = self.__generic_get__(get_type="ProductTags", token_type="", kv_dict=kv_dict)['productTags']
        # Cases where no Token is specified
        elif not token and token_type == ORGANIZATION:
            product_tags = self.__generic_get__(get_type="ProductTags", token_type=self.token_type, kv_dict=kv_dict)['productTags'] # getOrganizationProductTags
            for prod in product_tags:
                prod['type'] = PRODUCT
            project_tags = self.__generic_get__(get_type="ProjectTags", token_type=self.token_type, kv_dict=kv_dict)['projectTags']  # getOrganizationProductTags
            for prod in product_tags:
                prod['type'] = PROJECT
            ret = product_tags + project_tags
        elif not token and token_type == PRODUCT:
            ret = self.__generic_get__(get_type="ProjectTags", token_type=self.token_type, kv_dict=kv_dict)['projectTags'] # getProductProjectTags
        logging.debug(f"Getting {report_name} on {token_type} token: {token}")

        return ret

    def delete_scope(self,
                     token: str) -> dict:
        """
        :param token: token of entity to delete (product or project)
        :return: dict whether succeeded.
        :rtype dict
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if token_type == PROJECT:
            project = self.get_project(token)
            kv_dict[TOKEN_TYPES_MAPPING[PRODUCT]] = project[TOKEN_TYPES_MAPPING[PRODUCT]]
        logging.debug(f"Deleting {token_type}: {self.get_scope_name_by_token(token)} Token: {token}")

        return self.call_ws_api(f"delete{token_type.capitalize()}", kv_dict)

    def get_libraries(self,
                      search_value: str,
                      version: str = None,
                      search_only_name: bool = False,
                      global_search: bool = True) -> list:
        """
        :param search_only_name: Specify to return results that match the exact name
        :param version: Optional version of the searched library
        :param search_value: Search string to search
        :param global_search: whether to search global database.
        :return:
        """
        if global_search:
            logging.debug(f"Performing Global Search with value: \'{search_value}\'")
            libs = self.call_ws_api(request_type="librarySearch", kv_dict={"searchValue": search_value}).get('libraries')
            if version:
                logging.debug(f"Filtering search value: \'{search_value}\' by version: {version}")
                libs = [lib for lib in libs if lib.get('version') == version]
            if search_only_name:
                logging.debug(f"Filtering search results of search value \'{search_value}\' by exact name")
                libs = [lib for lib in libs if lib.get('name') == search_value]
            logging.info(f"Global search found {len(libs)} results for search value: \'{search_value}\'")
        else:
            libs = self.get_inventory()

        return libs

    def get_library_details(self,
                            name: str,
                            lib_type: str,
                            version: str,
                            architecture: str = None,
                            group: str = None,
                            language_version: str = None,
                            include_request_token: bool = False,
                            key_id: str = None,
                            languages: list = None) -> list:
        search_values = {"name": "libraryName",
                         "lib_type": "libraryType",
                         "version": "libraryVersion",
                         "architecture": "architecture",
                         "group": "libraryGroup",
                         "language_version": "languageVersion",
                         "include_request_token": "includeRequestToken",
                         "key_id": "keyId"}

        if lib_type == "Source Library" and languages:
            logging.debug(f"Replacing \"Source Library\" Type with {languages[0]}")
            lib_type = languages[0]

        if lib_type in LibTypes.type_to_lib_t.keys():
            logging.debug(f"Replacing {lib_type} Type with {LibTypes.type_to_lib_t[lib_type]}")
            lib_type = LibTypes.type_to_lib_t[lib_type]

        kv_dict = {}
        local_vars = locals()                                    # Iterating method variables to set search values
        for val in search_values.items():
            if local_vars[val[0]] is not None:
                kv_dict[val[1]] = local_vars[val[0]]
        ret = self.__generic_get__(get_type="LibraryInfo", token_type="", kv_dict=kv_dict).get('librariesInformation')

        return ret

    @check_permission(permissions=[ORGANIZATION])
    def set_alerts_status(self,
                          alert_uuids: Union[list, str],
                          status: str = None,
                          comments: str = None) -> dict:
        """
        :param alert_uuids: specify an alert's uuid or list of them
        :param status: status can be "Ignored" or "Active""
        :param comments: specify comment
        :return: dict whether succeeded
        :rtype dict
        """
        token_type, kv_dict = self.set_token_in_body()
        if not alert_uuids:
            logging.error("At least 1 alert uuid must be provided")
        elif status not in AlertStatus.ALERT_SET_STATUSES:
            logging.error(f'{status} status is invalid. Must be "Ignored" or "Active"')
        else:
            if isinstance(alert_uuids, str):
                alert_uuids = [alert_uuids]
            kv_dict['alertUuids'] = alert_uuids
            kv_dict['status'] = status
            kv_dict['comments'] = comments

            return self.call_ws_api(request_type='setAlertsStatus', kv_dict=kv_dict)

    def get_lib_notice(self,
                       product_token: str = None,
                       as_text: bool = False) -> Union[str, list]:
        """
        Method to return Notice text on all libs in a specified product
        :param product_token:
        :param as_text: If marked, will not try to convert text to LIST of DICTs
        :return: string or list of dictionaries
        """
        def __convert_notice_text_to_json__(text_str: str) -> list:
            """
            Method to convert Notice from text to LIST. If the 'text' value is also JSON it will be converted to dict
            :param text_str: The string to convert
            :return: list of dictionaries
            """
            def __append_notice_text_as_json__(c_d):
                try:
                    c_d['json'] = json.loads(c_d.get('text', ""))
                except json.JSONDecodeError:
                    logging.debug(f"No JSON to decode: {c_d.get('text')}")
                ret_list.append(c_d)

            ret_list = []
            lines = text_str.split('\r\n')
            lines = [line for line in lines if line.strip()]

            ret_text = text_str.replace('\r\n', "")

            for i in range(1, len(lines)):      # Starting for 1 to skip product name
                if lines[i].startswith('Library:'):
                    if 'curr_dict' in locals():
                        __append_notice_text_as_json__(curr_dict)
                    curr_dict = {'name': lines[i].replace('Library: ', "")}
                elif lines[i] == len(lines[i]) * lines[i][0]:
                    logging.debug(f"Skipping notice line: {lines[i]}")
                elif lines[i].startswith('Reference:'):
                    curr_dict['reference'] = lines[i].replace('Reference:', "")
                else:
                    curr_dict['text'] = curr_dict.get('text', "") + lines[i]
            __append_notice_text_as_json__(curr_dict)

            return ret_list

        token_type, kv_dict = self.set_token_in_body(token=product_token)

        if token_type == PRODUCT:
            ret = self.__generic_get__(get_type='NoticesTextFile', token_type="", kv_dict=kv_dict)
        else:
            raise ws_errors.WsSdkServerTokenTypeError(product_token)

        return ret if as_text else __convert_notice_text_to_json__(ret)

    @check_permission(permissions=[ORGANIZATION])
    def set_lib_notice(self,
                       lib_uuid: str,
                       text: Union[str, dict, list],
                       reference: str = None):
        token_type, kv_dict = self.set_token_in_body()
        kv_dict['libraryUUID'] = lib_uuid
        kv_dict['text'] = text if isinstance(text, str) else json.dumps(text)
        kv_dict['reference'] = reference

        return self.call_ws_api(request_type='setLibraryNotice', kv_dict=kv_dict)

    def get_policies(self,                                                  # TODO get affected policy (i.e include on each project product and org policies that affect the project
                     token: str = None,
                     include_parent_policy: bool = True) -> list:
        """
        Retrieves policies from scope
        :param token: Optional to to get policies of another token
        :param include_parent_policy: Should inherited policies be presented (default: true)
        :return: list of policies
        :rtype: list
        """
        report_name = "Policies"
        token_type, kv_dict = self.set_token_in_body(token)
        logging.debug(f"Running {token_type} {report_name}")
        kv_dict['aggregatePolicies'] = include_parent_policy
        ret = self.__generic_get__(get_type='Policies', token_type=token_type, kv_dict=kv_dict)['policies']
        pol_ctx2scope = {'DOMAIN': ORGANIZATION,
                         'PRODUCT': PRODUCT,
                         'PROJECT': PROJECT}

        for pol in ret:
            pol['scope_type'] = pol_ctx2scope[pol['policyContext']]

        return ret

    @check_permission(permissions=[ORGANIZATION])
    def create_user(self,
                    name: str,
                    email: str = None,
                    inviter_email: str = None,
                    is_service: bool = False) -> dict:
        """
        Create user or service user
        :param name: name of created user - if user exists, the method will fail
        :param email: 
        :param inviter_email: 
        :param is_service:
        :returns None if User, User Key if Service User
        :rtype: str None
        """
        token_type, kv_dict = self.set_token_in_body()
        ret = {}
        if self.get_users(name=name):                       # createUser WILL THROW AN ERROR IF CALLED ON EXISTING USER
            logging.warning(f"User: {name} already exists")
        elif is_service:
            logging.debug(f"Creating Service User: {name}")
            kv_dict['addedUser'] = {"name": name}
            ret = self.call_ws_api(request_type='createServiceUser', kv_dict=kv_dict)
        elif email and inviter_email:
            logging.debug(f"Creating User: {name} email : {email} with Inviter email: {inviter_email}")
            kv_dict['inviter'] = {"email": inviter_email}
            kv_dict['addedUser'] = {"name": name, "email": email}
            ret = self.call_ws_api(request_type='createUser', kv_dict=kv_dict)
        else:
            logging.error("Missing details to create User")

        return ret                                              #  TODO BUG IN CONFLUENCE DOCUMENTATION (userToken)

    @check_permission(permissions=[ORGANIZATION, GLOBAL])
    def delete_user(self,
                    email: str,
                    org_token: str = None) -> dict:
        """
        Remove user from organization by email address, If run by global and org_token is not None it will remove from
        a specific token and if not will remove from all organizations under global
        :param email: User's email to remove
        :param org_token: Delete from a specific org when running as Global administrator
        """
        if self.token_type == GLOBAL:
            orgs = self.get_organizations(token=org_token) if org_token else self.get_organizations()
            if orgs:
                for org in orgs:
                    temp_conn = copy(self)                      # TODO MAKE THIS GENERIC
                    temp_conn.token = org['token']
                    temp_conn.token_type = ORGANIZATION
                    temp_conn.delete_user(email)
            else:
                logging.error(f"Organization token: {org_token} was not found under Global Organization: {self.token}")
        else:
            if not self.get_users(email=email):
                logging.error(f"User's email: {email} does not exist in the organization")
            else:
                logging.debug(f"Deleting user email: {email} from Organization Token: {self.token}")
                return self.call_ws_api(request_type="removeUserFromOrganization", kv_dict={"user": {"email": email}})

    @check_permission(permissions=[ORGANIZATION])
    def create_group(self,
                     name: str,
                     description: str = None) -> dict:
        token_type, kv_dict = self.set_token_in_body()
        kv_dict['group'] = {"name": name,
                            "description": name if description is None else description,
                            }
        ret = {}
        if self.get_groups(name=name):
            logging.warning(f"Group: \'{name}\' already exists")
        else:
            logging.debug(f"Creating Group: {name}")
            ret = self.call_ws_api(request_type='createGroup', kv_dict=kv_dict)

        return ret

    @check_permission(permissions=[ORGANIZATION])
    def assign_user_to_group(self,
                             user_email: str,
                             group_name: str) -> dict:
        if not self.get_groups(name=group_name):
            logging.error(f"Unable to assign user: {user_email} to Group: {group_name}. Group does not exist")
        elif not self.get_users(email=user_email):
            logging.error(f"User's Email: {user_email} does not exist")
        elif self.get_groups(name=group_name, user_email=user_email):
            logging.warning(f"User's Email: {user_email} already in group: {group_name}")
        else:
            logging.debug(f"Assigning user's Email: {user_email} to Group: {group_name}")
            token_type, kv_dict = self.set_token_in_body()
            kv_dict['assignedUsers'] = [[{'name': group_name},
                                         [{"email": user_email}]
                                         ]]

            return self.call_ws_api(request_type='addUsersToGroups', kv_dict=kv_dict)

    @check_permission(permissions=[PRODUCT, ORGANIZATION])
    def assign_to_scope(self,
                        role_type: str,
                        token: str = None,
                        email: Union[str, list] = None,
                        group: Union[str, list] = None) -> dict:
        def __get_assignments__(a, key) -> list:
            assignments = []
            if isinstance(a, str):
                assignments = [{key: a}]
            elif isinstance(a, list):
                for e in a:
                    assignments.append({key: e})

            return assignments
        """
        Assign user(s) or group(s) to a designated scope (organization or product) with a specific role type
        :param role_type:
        :param token: Scope token (if no stated, assign to the connector scope
        :param email: User's email address (one or more)
        :param group: Group name (one or more)
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if not email and not group:
            logging.error("At least 1 user or group is required")
        elif token_type is ORGANIZATION and role_type not in RoleTypes.ORG_ROLE_TYPES:
            logging.error(f"Invalid {ORGANIZATION} Role type: {role_type}. Available Roles: {RoleTypes.PROD_ROLES_TYPES}")
        elif token_type is PRODUCT and role_type not in RoleTypes.PROD_ROLES_TYPES:
            logging.error(f"Invalid {PRODUCT} Role type: {role_type}. Available Roles: {RoleTypes.PROD_ROLES_TYPES}")
        else:
            all_groups_assignments = __get_assignments__(group, "name")         # Filter non-existing groups
            groups_assignments = []
            for group_item in all_groups_assignments:
                if self.get_groups(name=group_item['name']):
                    groups_assignments.append(group_item)
                else:
                    logging.warning(f"Group: {group_item} does not exist")
            groups_assignments = groups_assignments if len(groups_assignments) > 0 else None

            all_users_assignments = __get_assignments__(email, "email")          # Filter non-existing users in the org
            users_assignments = []
            for user_item in all_users_assignments:
                if self.get_users(email=user_item['email']):
                    users_assignments.append(user_item)
                else:
                    logging.warning(f"User email: {user_item['email']} does not exist")

            if users_assignments or groups_assignments:
                kv_dict[role_type] = {'userAssignments': users_assignments,
                                      'groupAssignments': groups_assignments}
                logging.debug(f"Assigning User(s): {email} Group(s): {group} to Role: {role_type}")
                return self.__generic_set__(set_type='Assignments', token_type=token_type, kv_dict=kv_dict)
            else:
                logging.error("No valid user or group were found")

