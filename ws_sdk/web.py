import json
import logging
from datetime import datetime
from secrets import compare_digest
from typing import Union

from . import ws_utilities, ws_errors
import requests
from memoization import cached

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
                        raise ws_errors.TokenTypeError
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
                 url: str,
                 user_key: str,
                 token: str,
                 token_type: str = ORGANIZATION,
                 timeout: int = CONN_TIMEOUT,
                 resp_format: str = "json"
                 ):
        """WhiteSource Python SDK
        :api_url: URL for the API to access (e.g. saas.whitesourcesoftware.com)
        :user_key: User Key to use
        :token: Token of scope
        :token_type: Scope Type (organization, product, project)
        """
        self.user_key = user_key
        self.token = token
        self.token_type = token_type
        self.timeout = timeout
        self.resp_format = resp_format

        if url in ['saas', 'saas-eu', 'app', 'app-eu']:
            self.url = f"https://{url}.whitesourcesoftware.com"
        else:
            self.url = url
        self.api_url = self.url + API_URL_SUFFIX

        if not ws_utilities.is_token(self.user_key):
            logging.warning(f"Invalid User Key: {self.user_key}")

    @cached(ttl=CACHE_TIME)
    def __set_token_in_body__(self,
                              token: str = None) -> (str, dict):
        kv_dict = {}
        if token is None:
            token_type = self.token_type
        else:
            token_type = self.get_scope_type_by_token(token)
            kv_dict[TOKEN_TYPES[token_type]] = token
            logging.debug(f"Token: {token} is a {token_type}")

        return token_type, kv_dict

    @cached(ttl=CACHE_TIME)
    def __create_body__(self,
                        api_call: str,
                        kv_dict: dict = None) -> dict:
        ret_dict = {
            "requestType": api_call,
            "userKey": self.user_key,
            TOKEN_TYPES[self.token_type]: self.token
        }
        if isinstance(kv_dict, dict):
            for ent in kv_dict:
                ret_dict[ent] = kv_dict[ent]

        return ret_dict

    @cached(ttl=CACHE_TIME)
    def __call_api__(self,
                     request_type: str,
                     kv_dict: dict = None) -> dict:
        body = self.__create_body__(request_type, kv_dict)
        token = [s for s in body.keys() if 'Token' in s]
        try:
            resp = requests.post(self.api_url, data=json.dumps(body), headers=HEADERS, timeout=self.timeout)
        except requests.RequestException:
            logging.exception(f"Received Error on {body[token[-1]]}")
            raise

        if resp.status_code > 299 or "errorCode" in resp.text:
            logging.error(f"API {body['requestType']} call on {body[token[-1]]} failed: {resp.text}")
            raise requests.exceptions.RequestException
        else:
            logging.debug(f"API {body['requestType']} call on {token[-1]} {body[token[-1]]} succeeded")

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

    @cached(ttl=CACHE_TIME)
    def __generic_get__(self,
                        get_type: str,
                        token_type: str = None,
                        kv_dict: dict = None) -> [list, dict, bytes]:
        """
        This function completer the API type and calls.
        :param get_type:
        :param token_type:
        :param kv_dict:
        :return: can be list, dict, none or bytes (pdf, xlsx...)
        :rtype: list or dict or bytes
        """
        if token_type is None:
            token_type = self.token_type

        return self.__call_api__(f"get{token_type.capitalize()}{get_type}", kv_dict)

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
                   report: bool = False) -> Union[list, bytes]:
        """
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
        token_type, kv_dict = self.__set_token_in_body__(token)
        if alert_type in AlertTypes.ALERT_TYPES:
            kv_dict["alertType"] = alert_type
        elif alert_type:
            logging.error(f"Alert: {alert_type} does not exist")
            return

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
            ret = self.__generic_get__(get_type='IgnoredAlertsReport', token_type=token_type, kv_dict=kv_dict)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        return self.get_scopes(token=token)[0]

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
        def __enrich_projects__(proj_list: list, prod_list: dict):
            for project in proj_list:
                project['type'] = PROJECT
                project['productToken'] = prod_list.get('token')
                project['productName'] = prod_list.get('name')

            return proj_list

        def __get_projects_from_product__(products: list):
            all_projs = []
            for p in products:
                try:
                    projects = self.__generic_get__(get_type="ProjectVitals", kv_dict={'productToken': p['token']}, token_type='product')['projectVitals']
                    all_projs.extend(__enrich_projects__(projects, p))
                except KeyError:
                    logging.debug(f"Product: {p['name']} Token {p['token']} without projects. Skipping")
            return all_projs

        def __create_self_scope__() -> dict:
            return {'type': self.token_type,
                    'token': self.token,
                    'name': self.get_name()}

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
                if product['token'] == product_token:
                    prod_token_exists = True
                if 'type' not in product:
                    product['type'] = PRODUCT

            if not prod_token_exists and product_token is not None:
                raise ws_errors.MissingTokenError(product_token, self.token_type)

            if scope_type not in [ORGANIZATION, PRODUCT]:
                all_projects = __get_projects_from_product__(all_products)
                scopes.extend(all_projects)
            if scope_type not in [ORGANIZATION, PROJECT]:
                scopes.extend(all_products)
            if scope_type in [ORGANIZATION, None]:
                scopes.append(self.get_organization_details())
        else:
            scopes.append(__create_self_scope__())
        # Filter scopes
        if token:
            scopes = [scope for scope in scopes if compare_digest(scope['token'], token)]
            if not scopes:
                raise ws_errors.MissingTokenError(token, self.token_type)
        if name:
            scopes = [scope for scope in scopes if scope['name'] == name]
        if scope_type is not None:                                              # 2nd filter because scopes may contain full scope due to caching
            scopes = [scope for scope in scopes if scope['type'] == scope_type]
        if product_token:
            scopes = [scope for scope in scopes if scope.get('productToken') == product_token]

        return scopes

    @check_permission(permissions=[ORGANIZATION])
    def get_organization_details(self) -> dict:
        org_details = None
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
        :param status: str Alert status: "Active", "Ignored", "Resolved"
        :param container:
        :param cluster:
        :param report:
        :param token: The token that the request will be created on
        :return: list or xlsx if report is True
        :rtype: list or bytes
        """
        token_type, kv_dict = self.__set_token_in_body__(token)
        if not report:
            kv_dict["format"] = "json"
        if status is not None:
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
            libs_vul[key_uuid]['lib_url'] = f"{self.url}/Wss/WSS.html#!libraryDetails;uuid={key_uuid};{TOKEN_TYPES[self.token_type]}={self.token}"
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
        def get_spdx() -> dict:
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

            return licenses_dict

        def fix_license(lic: dict) -> None:
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

        def enrich_lib(library: dict, spdx: dict):
            for lic in library.get('licenses'):
                fix_license(lic)                                        # Manually fixing this license
                try:
                    lic['spdx_license_dict'] = spdx[lic['spdxName']]
                    logging.debug(f"Found license: {lic['spdx_license_dict']['licenseId']}")
                except KeyError:
                    logging.warning(f"License with identifier: {lic['name']} was not found")

        report_name = 'licenses'
        token_type, kv_dict = self.__set_token_in_body__(token)
        if histogram:
            logging.debug(f"Running {token_type} {report_name} Histogram")
            ret = self.__generic_get__(get_type='LicenseHistogram', token_type=token_type, kv_dict=kv_dict)['licenseHistogram']
        else:
            logging.debug(f"Running {token_type} {report_name}")
            kv_dict['excludeProjectOccurrences'] = exclude_project_occurrences
            ret = self.__generic_get__(get_type='Licenses', token_type=token_type, kv_dict=kv_dict)['libraries']

            if full_spdx:
                spdx_dict = get_spdx()
                for lib in ret:
                    enrich_lib(lib, spdx_dict)

        return ret

    @report_metadata(report_bin_type="xlsx")
    def get_source_files(self,
                         token: str = None,
                         report: bool = False) -> Union[list, bytes]:
        report_name = 'Source File Inventory Report'
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
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

    def get_assignments(self,
                        token: str = None,
                        role_type: str = None,
                        entity_type: str = None) -> list:
        """
        :param token: scope token to retrieve assignments
        :param role_type: accepted roles: DEFAULT_APPROVER, PRODUCT_INTEGRATOR, ADMIN
        :param entity_type: whether to filter user or group assignments.
        :return: flat list of of entities (users and groups) with their role, type and token
        :rtype list
        """
        report_name = "Assignment"
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
        if report and token_type == PROJECT:
            logging.error(f"{report_name} report is unsupported on {token_type}")
        elif report:
            logging.debug(f"Running {report_name} report on {token_type}")
            ret =  self.__generic_get__(get_type='LibraryLocationReport', token_type=token_type, kv_dict=kv_dict)
        elif not report and token_type == ORGANIZATION:
            logging.error(f"{report_name} is unsupported on {token_type}")
            ret = None
        else:
            logging.debug(f"Running {report_name} on {token_type}")
            ret =  self.__generic_get__(get_type='LibraryLocations', token_type=token_type, kv_dict=kv_dict)

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
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        report_name = "Attribution Report"
        token_type, kv_dict = self.__set_token_in_body__(token)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
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
            token_type, kv_dict = self.__set_token_in_body__(token)
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
        token_type, kv_dict = self.__set_token_in_body__(token)
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
            return self.get_scope_by_token(token=project_scope['productToken'])

    def get_project(self,
                    token: str) -> dict:
        all_projects = self.get_projects()
        for project in all_projects:
            if compare_digest(project['token'], token):
                return project
        logging.error(f"Project with token: {token} was not found")

    @check_permission(permissions=[ORGANIZATION])
    def get_users(self) -> list:
        report_name = 'Users'
        token_type, kv_dict = self.__set_token_in_body__()

        return self.__generic_get__(get_type='AllUsers', token_type="")['users']

    def get_tags(self,
                 token: str = None) -> list:
        report_name = "Tags"
        token_type, kv_dict = self.__set_token_in_body__(token)

        if token and token_type == PROJECT or self.token_type == PROJECT:                              # getProjectTags
            ret = self.__generic_get__(get_type="ProjectTags", token_type="", kv_dict=kv_dict)['projectTags']
        elif token and token_type == PRODUCT:                                                          # getProductTags
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
        token_type, kv_dict = self.__set_token_in_body__(token)
        if token_type == PROJECT:
            project = self.get_project(token)
            kv_dict['productToken'] = project['productToken']
        logging.debug(f"Deleting {token_type}: {self.get_scope_name_by_token(token)} Token: {token}")

        return self.__call_api__(f"delete{token_type.capitalize()}", kv_dict)

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
            libs = self.__call_api__(request_type="librarySearch", kv_dict={"searchValue": search_value}).get('libraries')
            if version:                                                     # Filtering by version # TODO Good idea to extend with <>~
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
        token_type, kv_dict = self.__set_token_in_body__()
        if not alert_uuids:
            logging.error(f"alert_uu_ids must be provided")
        elif status not in ALERT_STATUSES:
            logging.error(f'{status} status is not allowed. Must be "Ignored" or "Active"')
        else:
            if isinstance(alert_uuids, str):
                alert_uuids = [alert_uuids]
            kv_dict['alertUuids'] = alert_uuids
            kv_dict['status'] = status
            kv_dict['comments'] = comments

            return self.__call_api__(request_type='setAlertsStatus', kv_dict=kv_dict)
