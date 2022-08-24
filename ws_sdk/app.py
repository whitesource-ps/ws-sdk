import json
import uuid
from copy import copy

from datetime import datetime
from logging import getLogger
from time import sleep
from typing import Union, List
import requests
from requests.adapters import HTTPAdapter
import time
import io
import zipfile

from ws_sdk import ws_utilities
from ws_sdk._version import __version__, __tool_name__
from ws_sdk.ws_constants import *
from ws_sdk.ws_errors import *

logger = getLogger(__name__)


class WSApp:
    class Decorators:
        @classmethod
        def report_metadata(cls, **kwargs_metadata):
            def decorator(function):
                def wrapper(*args, **kwargs):
                    if len(args) == 2 and args[1] in ReportsMetaData.REPORTS_META_DATA:
                        return kwargs_metadata.get(args[1])
                    else:
                        return function.__call__(*args, **kwargs)

                return wrapper
            return decorator

        @classmethod
        def check_permission(cls, permissions: list):  # Decorator to enforce WS scope token types
            def decorator(function):
                def wrapper(*args, **kwargs):
                    def __get_token_type__():  # Internal method to get token_type from args or kwargs
                        token_type = kwargs.get('token_type')
                        if token_type is None:
                            try:
                                token_type = args[0].token_type
                            except IndexError:
                                logger.exception("Unable to discover token type")
                                raise WsSdkServerTokenTypeError
                        return token_type

                    if __get_token_type__() in permissions:
                        return function.__call__(*args, **kwargs)
                    else:
                        logger.error(f"Token Type: {args[0].token_type} is unsupported to execute: {function.__name__}")

                return wrapper

            return decorator

    @classmethod
    def get_reports_meta_data(cls, scope: str = None) -> list:
        """
        Function to return report functions based on metadata on the function
        :param cls:
        :param scope: Whether to filter reports based on scope (i.e. which reports can run on project level)
        :return: list of NamedTuples containing function name and function.
        """
        report_funcs = list()
        class_dict = dict(WSApp.__dict__)
        for f in class_dict.items():
            if cls.Decorators.report_metadata.__name__ in str(f[1]) and (not scope or scope in f[1](None, ReportsMetaData.REPORT_SCOPE)):
                report_funcs.append(
                    ReportsMetaData(name=f[0].replace('get_', ''), bin_sfx=f[1](None, ReportsMetaData.REPORT_BIN_TYPE), func=f[1]))

        return report_funcs

    @classmethod
    def get_report_types(cls, scope: str = None) -> list:
        """
        Method to return report types based on metadata on the function
        :param cls:
        :param scope: Whether to filter based on scope
        :return: list of report names (without get_ function prefix)
        """
        return [f.name for f in cls.get_reports_meta_data(scope)]

    def __init__(self,
                 user_key: str,
                 token: str,
                 url: str = None,
                 token_type: str = ScopeTypes.ORGANIZATION,
                 timeout: int = CONN_TIMEOUT,
                 resp_format: str = "json",
                 tool_details: tuple = (f"ps-{__tool_name__.replace('_','-')}", __version__),
                 **kwargs
                 ):
        """WhiteSource Python SDK
        :url: URL for the API to access (e.g. saas.whitesourcesoftware.com)
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
        self.session = requests.session()
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retry_strategy)
        self.session.mount(prefix='https://', adapter=adapter)
        self.url = ws_utilities.get_full_ws_url(url)
        self.api_url = self.url + API_URL_SUFFIX
        self.header_tool_details = {"agent": tool_details[0], "agentVersion": tool_details[1]}
        self.headers = {**WS_HEADERS,
                        **self.header_tool_details,
                        'ctxId': uuid.uuid1().__str__()}
        self.scope_contains = set()

        if not ws_utilities.is_token(self.user_key):
            raise WsSdkTokenError(self.user_key)

    @property
    def spdx_lic_dict(self):
        return ws_utilities.get_spdx_license_dict()

    def get_scope_type_bytoken(self, token : str):
        token_type = "project"
        try:
            rt = self.call_ws_api(request_type="getProjectVitals",
                                kv_dict={"projectToken": token})
        except:
            token_type = "product"
            try:
                rt = self.call_ws_api(request_type="getProductProjectVitals",
                                      kv_dict={"productToken": token})
            except:
                token_type = "organization"
                try:
                    rt = self.call_ws_api(request_type="getOrganizationProjectVitals",
                                          kv_dict={"orgToken": token})
                except:
                    token_type = self.token_type

        return token_type

    def set_token_in_body(self,
                          token: Union[str, tuple] = None) -> (str, dict):
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
        elif isinstance(token, tuple):
            token_type = token[1]
            token = token[0]
            kv_dict[TOKEN_TYPES_MAPPING[token_type]] = token
        else:
            #token_type = self.get_scope_type_by_token(token)
            token_type = self.get_scope_type_bytoken(token)  # For getting token_type need just fast checking
            kv_dict[TOKEN_TYPES_MAPPING[token_type]] = token
        logger.debug(f"Token: '{token}' is a {token_type}")

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

            toks = [k for k in ret_dict.keys() if k in TOKEN_TYPES_MAPPING.values()]  # If scope token already configured
            if toks:
                tok = toks[0]
            else:
                ret_dict[TOKEN_TYPES_MAPPING[self.token_type]] = self.token
                tok = TOKEN_TYPES_MAPPING[self.token_type]

            return tok, ret_dict

        def __handle_ws_server_errors(error):
            def extract_error_message(err: str) -> dict:
                return json.loads(err)

            """
            2001 - Product name occupied
            2007 - User is not in Organization
            2008 - Group does not exist
            2010 - Project name occupied
            2011 - User doesn't exist
            2013 - Invitation was already sent to this user, User name contains not allowed characters
            2015 - Inactive org
            2021 - Invalid option value for property
            3000 - Invalid request parameters
            3010 - Missing fields: user
            4000 - Unexpected error
            5001 - User is not allowed to perform this action
            8000 - Invalid key UUID
            :param error:
            """
            error_dict = extract_error_message(error)
            if error_dict['errorCode'] == 2015:
                raise WsSdkServerInactiveOrg(body[token])
            elif error_dict['errorCode'] == 5001:
                raise WsSdkServerInsufficientPermissions(body['userKey'])
            elif error_dict['errorCode'] == 2013:
                logger.warning(error_dict['errorMessage'])
            elif error_dict['errorCode'] in [2001, 2010]:
                logger.warning(error_dict['errorMessage'])
                scope = body['requestType'].lstrip("create")
                raise WsSdkServerScopeExists(scope_type=scope, scope_name=body[f"{scope.lower()}Name"])
            elif error_dict['errorCode'] == 8000:
                raise WsSdkServerInvalidLibUuid(body[token], body['targetKeyUuid'])
            else:
                raise WsSdkServerGenericError(body[token], error)

        token, body = __create_body(request_type, kv_dict)
        logger.debug(f"Calling: {self.api_url} with requestType: {request_type}")

        tries_left = retry_strategy.total
        is_success = False
        while tries_left and not is_success:
            tries_left -= 1
            try:
                resp = self.session.post(url=self.api_url, data=json.dumps(body), headers=self.headers, timeout=self.timeout)
                resp.raise_for_status()
                is_success = True
            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.HTTPError):
                    logger.exception(f"API '{body['requestType']}' call on '{body.get(token)}' failed with error code: {resp.status_code}.\nError Body: '{resp.text}'. {tries_left} tries left")
                else:
                    logger.exception(f"Error generating request: '{body['requestType']}' on '{body.get(token)}'. {tries_left} tries left")

                if tries_left == 0:
                    raise
                else:
                    sleep(5)

        if "errorCode" in resp.text:
            logger.debug(f"API returned errorCode {body['requestType']} call on {body[token]} message: {resp.text}")
            __handle_ws_server_errors(resp.text)
        else:
            logger.debug(f"API {body['requestType']} call on {token} {body[token]} succeeded")

        try:
            ret = json.loads(resp.text)
        except json.JSONDecodeError:
            logger.debug("Response is not a JSON object")
            if resp.encoding is None:
                logger.debug("Response is binary")
                ret = resp.content
            else:
                logger.debug(f"Response encoding: {resp.encoding}")
                ret = resp.text

        return ret

    def _generic_get(self,
                     get_type: str,
                     token_type: str = None,
                     kv_dict: dict = None) -> [list, dict, bytes]:
        """
        This function completes the API type and calls.
        :param get_type: API name (without get prefix and can dynamically assign <Scope> value according to connector type)
        :param token_type: Explicitly specifying token scope type.
        :param kv_dict: Dictionary with additional body data
        :return: can be list, dict, none or bytes (pdf, xlsx...)
        :rtype: list or dict or bytes
        """
        if token_type is None:
            token_type = self.token_type

        return self.call_ws_api(request_type=f"get{token_type.capitalize()}{get_type}", kv_dict=kv_dict)

    def _generic_set(self,
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

        return self.call_ws_api(request_type=f"set{token_type.capitalize()}{set_type}", kv_dict=kv_dict)

    # Covers O/P/P + byType + report
    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_alerts(self,                                                 #TODO REQUIRES A NICE REFACTOR
                   token: str = None,
                   alert_type: str = None,
                   from_date: datetime = None,
                   to_date: datetime = None,
                   tags: dict = None,
                   ignored: bool = False,
                   resolved: bool = False,
                   report: bool = False,
                   asyncr: bool = False) -> Union[list, bytes, None]:
        """
        Retrieves open alerts of all types
        :param asyncr:get output using async API call
        :param token: The token that the request will be created on
        :param alert_type: Allows filtering alerts by a single type from ALERT_TYPES
        :param from_date: Allows filtering of alerts by start date. Works together with to_date
        :param to_date: Allows filtering of alerts by end date. Works together with from_date
        :param tags: filter by tags in form of Key:Value dict. only 1 is allowed.
        :param ignored: Should output include ignored reports
        :param resolved: Should output include resolved reports
        :param report: Create xlsx report type
        :return: list with alerts or xlsx if report is True
        :rtype: list or bytes or dict
        """
        name = "Alerts"
        token_type, kv_dict = self.set_token_in_body(token)
        if alert_type in AlertTypes.ALERT_TYPES:
            kv_dict["alertType"] = alert_type
        elif alert_type:
            logger.error(f"Alert: {alert_type} does not exist")
            return None

        if isinstance(from_date, datetime):
            kv_dict["fromDate"] = from_date.strftime(DATE_FORMAT)
        if isinstance(to_date, datetime):
            kv_dict["toDate"] = to_date.strftime(DATE_FORMAT)

        ret = None
        if resolved and report:
            logger.debug(f"Running Resolved {name} Report")
            ret = self._generic_get(get_type='ResolvedAlertsReport', token_type=token_type, kv_dict=kv_dict)
        elif report:
            logger.debug(f"Running {name} Report")
            kv_dict["format"] = "xlsx"
            if asyncr:
                kv_dict['reportType'] = f"{token_type.capitalize()}SecurityAlertsReport"
                ret = self.async_report_generation(token_type, kv_dict, report)
            else:
                ret = self._generic_get(get_type='SecurityAlertsByVulnerabilityReport', token_type=token_type, kv_dict=kv_dict)
        elif resolved:
            logger.error(f"Resolved {name} is only available in xlsx format(set report=True)")
        elif ignored:
            logger.debug(f"Running ignored {name}")
            ret = self._generic_get(get_type='IgnoredAlerts', token_type=token_type, kv_dict=kv_dict)
        elif tags:
            if token_type != ScopeTypes.ORGANIZATION:
                logger.error("Getting project alerts tag is only supported with organization token")
            elif len(tags) == 1:
                logger.debug("Running Alerts by project tag")
                ret = self._generic_get(get_type='AlertsByProjectTag', token_type=token_type, kv_dict=kv_dict)
            else:
                logger.error("Alerts tag is not set correctly")
        elif kv_dict.get('alertType') is not None:
            logger.debug("Running Alerts By Type")
            ret = self._generic_get(get_type='AlertsByType', token_type=token_type, kv_dict=kv_dict)
        else:
            logger.debug("Running Alerts")
            kv_dict["format"] = "json"
            if asyncr:
                kv_dict['reportType'] = f"{token_type.capitalize()}SecurityAlertsReport"
                ret = self.async_report_generation(token_type, kv_dict, report)
            else:
                ret = self._generic_get(get_type='SecurityAlertsByVulnerabilityReport', token_type=token_type, kv_dict=kv_dict)

        return ret.get('alerts') if isinstance(ret, dict) and 'alerts' in ret else ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_ignored_alerts(self,
                           token: str = None,
                           report: bool = False,
                           asyncr: bool = False) -> Union[list, bytes]:
        return self.get_alerts(token=token, report=report, ignored=True, asyncr=False)

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_resolved_alerts(self,
                            token: str = None,
                            report: bool = False,
                            asyncr: bool = False) -> Union[list, bytes]:
        return self.get_alerts(token=token, report=report, resolved=True, asyncr=False)

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_inventory(self,
                      lib_name: str = None,
                      token: str = None,
                      include_in_house_data: bool = True,
                      as_dependency_tree: bool = False,
                      with_dependencies: bool = False,
                      report: bool = False,
                      asyncr: bool = False) -> Union[List[dict], bytes]:
        """
        : param asyncr:get output using async API call
        : returns list or bytes or dict
        """
        def enrich_dependency(ret, with_dependencies, lib_name):
            ret = ret.get('libraries', []) if isinstance(ret, dict) else []
            if with_dependencies:
                main_l = []
                [get_deps(lib, None, main_l) in lib for lib in ret]
                ret = main_l
            if lib_name:
                ret = [lib for lib in ret if lib['name'] == lib_name]
            return ret

        def get_deps(library: dict, parent_lib: dict, main_list: list):
            deps = library.get('dependencies')
            if deps:
                for d in deps:
                    get_deps(d, library, main_list)

            if parent_lib:
                logger.debug(f"Library '{library['filename']}' is a dependency of library '{parent_lib['filename']}'")
                library['is_dependency_of'] = parent_lib
            else:
                if library.get('filename') is not None:
                    library_debug = library.get('filename')
                else:
                    library_debug = library.get('name')
                logger.debug(f"Library '{library_debug}' is a direct dependency")        # THIS MAY NOT BE ALWAYS TRUE

            main_list.append(library)

        """
        :param name: filter libs by name (only in JSON)
        :param as_dependency_tree: Include library dependency (Project Hierarchy)
        :param token: The token that the request will be created on
        :param include_in_house_data:
        :param with_dependencies: return flat list of all libs in project including transient
        :param report: Get data in binary form
        :return: list or xlsx if report is True
        :rtype: list or bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        name = 'Inventory'
        kv_dict["format"] = "xlsx" if report else "json"
        if token_type == ScopeTypes.PROJECT and not include_in_house_data:
            kv_dict["includeInHouseData"] = include_in_house_data
            logger.debug(f"Running {token_type} {name}")
            ret = self._generic_get('Inventory', token_type=token_type, kv_dict=kv_dict)
        elif token_type == ScopeTypes.PROJECT and (as_dependency_tree or with_dependencies):
            logger.debug(f"Running {token_type} Hierarchy")
            ret = self._generic_get(get_type="Hierarchy", token_type=token_type, kv_dict=kv_dict)
        else:
            if asyncr:
                kv_dict['reportType'] = f"{token_type.capitalize()}InventoryReport"
                ret = self.async_report_generation(token_type, kv_dict, report)
            else:
                logger.debug(f"Running {token_type} {name} Report")
                ret = self._generic_get(get_type="InventoryReport", token_type=token_type, kv_dict=kv_dict)

        if not report and isinstance(ret, dict):
            for key, value in ret.items():
                if 'asyncReport' in key:
                    ret[key] = enrich_dependency(value, with_dependencies, lib_name)
                elif 'libraries' in key:
                    ret = enrich_dependency(ret, with_dependencies, lib_name)

        return ret

    @Decorators.report_metadata(report_scope_types=[ScopeTypes.PROJECT])
    def get_lib_dependencies(self,
                             key_uuid: str,
                             report: bool = False,
                             token: str = None,
                             asyncr: bool = False,) -> list:
        """
        Method to get lib dependencies (and dependencies of dependencies...) by  keyUuid
        :param key_uuid:
        :param report:
        :param token:
        :return: list of dependency libs
        """
        name = "Lib Dependency"
        token_type, kv_dict = self.set_token_in_body(token)
        ret = None
        if report:
            logger.error(f"{name} is not support as report")
        elif token_type == ScopeTypes.PROJECT:
            kv_dict["keyUuid"] = key_uuid
            ret = self._generic_get(get_type="LibraryDependencies", token_type=token_type, kv_dict=kv_dict)
        else:
            logger.error(f"Method is only supported with organization token")

        return ret

    def get_lib(self, name: str):
        ret = self.get_inventory(lib_name=name)

        if ret:
            return ret[0]
        else:
            raise WsSdkServerInvalidLibName(self.token, name)

    def get_lib_uuid(self, name: str):
        return self.get_lib(name=name)['keyUuid']

    def get_scope_type_by_token(self,
                                token: str) -> str:
        return self.get_scope_by_token(token)['type']

    def get_scope_name_by_token(self,
                                token: str) -> str:
        return self.get_scope_by_token(token)['name']

    def get_scope_by_token(self,
                           token: str,
                           token_type: str = None) -> dict:
        """
        Method to return the scope of a token, if not found, raise exception.
        :param token: the searched token
        :param token_type: Ability to pass token type for performance
        :return: dictionary of scope
        :rtype: dict
        """
        ret = None
        if token_type is None and self.token_type == ScopeTypes.PRODUCT:
            token_type = ScopeTypes.PROJECT

        if token_type == ScopeTypes.PROJECT:
            ret = self.get_projects(token=token)
        elif token_type == ScopeTypes.PRODUCT:
            ret = self.get_products(token=token)
        elif self.token_type == ScopeTypes.ORGANIZATION:
            ret = self.get_products(token=token)
            if not ret:
                ret = self.get_projects(token=token)

        if ret:
            ret = ret[0]
        else:
            raise WsSdkServerMissingTokenError(token, self.token_type)

        return ret

    @classmethod
    def sort_and_filter_scopes(cls,
                               scopes: list,
                               token: str = None,
                               name: str = None,
                               scope_type: str = None,
                               product_token: str = None,
                               product_name: str = None,
                               sort_by: str = None):
        if token:
            scopes = [scope for scope in scopes if scope['token'] == token]
        if name:
            scopes = [scope for scope in scopes if scope['name'] == name]
        if scope_type is not None:
            scopes = [scope for scope in scopes if scope['type'] == scope_type]
        if product_token:
            scopes = [scope for scope in scopes if scope.get(TOKEN_TYPES_MAPPING[ScopeTypes.PRODUCT]) == product_token]
        if product_name:
            scopes = [p for p in scopes if p.get(TOKEN_TYPES_MAPPING[ScopeTypes.PRODUCT]) == product_name]

        if sort_by:
            if sort_by in ScopeSorts.SCOPE_SORTS:
                logger.debug(f"Sorting scope by: {sort_by}")
                if sort_by is not ScopeSorts.NAME:
                    for s in scopes:
                        s[sort_by] = ws_utilities.convert_to_time_obj(s[sort_by.rstrip("_obj")])

                scopes = sorted(scopes, key=lambda d: d[sort_by])
            else:
                logger.error(f"{sort_by} is not a valid sort option")

        return scopes

    def _enrich_products(self, products):
        for product in products:
            product['type'] = ScopeTypes.PRODUCT
            product['org_token'] = self.token

        return products

    def get_scopes(self,
                   name: str = None,
                   token: str = None,
                   scope_type: str = None,
                   product_token: str = None,
                   product_name: str = None,
                   sort_by: str = None,
                   include_prod_proj_names: bool = True) -> list:
        """
        :param name: filter returned scopes by name
        :param token: filter by token
        :param scope_type: filter by scope type
        :param product_token: filter projects by product token
        :param product_name:
        :param sort_by: Sort returned list
        :param include_prod_proj_names:
        :return: list of scope dictionaries
        :rtype list
        """
        def _create_self_scope() -> dict:
            return {'type': self.token_type,
                    'token': self.token,
                    'name': self.get_name()}

        def enrich_orgs(orgs) -> list:
            for o in orgs:
                o['global_token'] = self.token
                o['name'] = o['orgName']
                o['token'] = o['orgToken']
                o['type'] = ScopeTypes.ORGANIZATION

            return orgs

        scopes = []
        need_filter = True
        if self.token_type == ScopeTypes.PRODUCT:
            scopes = self.get_projects(name=name,
                                       product_token=product_token,
                                       product_name=product_name,
                                       sort_by=sort_by,
                                       include_prod_proj_names=include_prod_proj_names)
            if not scope_type:
                product = _create_self_scope()
                scopes.append(product)
            need_filter = False
        elif self.token_type == ScopeTypes.ORGANIZATION and scope_type == ScopeTypes.PROJECT:
            scopes = self.get_projects(name=name,
                                       product_token=product_token,
                                       product_name=product_name,
                                       sort_by=sort_by,
                                       include_prod_proj_names=include_prod_proj_names)
            need_filter = False
        elif self.token_type == ScopeTypes.ORGANIZATION and scope_type == ScopeTypes.PRODUCT:
            all_products = self._generic_get(get_type="ProductVitals")['productVitals']
            prod_token_exists = False
            all_products = self._enrich_products(all_products)

            for product in all_products:                                    # TODO CHANGE THIS
                if product['token'] == token:
                    logger.debug(f"Found searched token: {token}")
                    scopes.append(product)
                    return scopes
                elif product['token'] == product_token:
                    logger.debug(f"Found searched productToken: {token}")
                    prod_token_exists = True
                    break

            if not prod_token_exists and product_token is not None:
                raise WsSdkServerMissingTokenError(product_token, self.token_type)
            if scope_type not in [ScopeTypes.ORGANIZATION, ScopeTypes.PRODUCT]:
                if product_token:
                    all_products = [prod for prod in all_products if prod['token'] == product_token]
                all_projects = self._get_projects_from_product(all_products)
                scopes.extend(all_projects)
            if scope_type not in [ScopeTypes.ORGANIZATION, ScopeTypes.PROJECT]:
                scopes.extend(all_products)
            if scope_type in [ScopeTypes.ORGANIZATION, None]:
                scopes.append(self.get_organization_details())
        elif self.token_type == ScopeTypes.GLOBAL:
            organizations = self._generic_get(get_type="AllOrganizations", token_type="")['organizations']
            self.scope_contains.add(ScopeTypes.ORGANIZATION)
            organizations = enrich_orgs(organizations)

            scopes = []
            if scope_type in [ScopeTypes.PROJECT, ScopeTypes.PRODUCT]:
                for org in organizations:
                    temp_conn = WSApp(url=self.url,
                                      user_key=self.user_key,
                                      token=org['orgToken'],
                                      token_type=ScopeTypes.ORGANIZATION)
                    try:
                        scopes.extend(temp_conn.get_scopes(scope_type=scope_type))
                        org['active'] = True
                        self.scope_contains.add(scope_type)
                    except WsSdkServerInactiveOrg as e:
                        logger.warning(e.message)
                        org['active'] = False
            else:
                scopes.extend(organizations)
                scopes.append(_create_self_scope())
        elif self.token_type == ScopeTypes.PROJECT:
            scopes.append(_create_self_scope())
        elif self.token_type == ScopeTypes.ORGANIZATION and scope_type == ScopeTypes.ORGANIZATION:
            scopes.append(_create_self_scope())
        else:
            products = self.get_products()
            projects = self.get_projects()

            scopes = products + projects + [_create_self_scope()]

        if need_filter:
            scopes = self.sort_and_filter_scopes(scopes, token, name, scope_type, product_token, product_name)

        logger.debug(f"{len(scopes)} results were found")       # Check that MissingTokenError is not in use in other repos

        return scopes

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_organization_details(self) -> dict:
        org_details = self._generic_get(get_type='Details')
        org_details['name'] = org_details.get('orgName')
        org_details['token'] = self.token
        org_details['type'] = ScopeTypes.ORGANIZATION

        return org_details

    def get_name(self) -> str:
        """
        Method to return self name of token configured in SDK
        :return: name of configured in SDK
        :rtype: str
        """
        if self.token_type == ScopeTypes.ORGANIZATION:
            return self.get_organization_details()['orgName']
        elif self.token_type == ScopeTypes.GLOBAL:
            return "Global Organization"
        else:
            return self.get_tags()[0]['name']

    def get_scopes_from_name(self,
                             name: str,
                             token_type: str = None) -> list:
        """
        Method to return scope list of dictionaries from name
        :param name: the name of scope to return
        :param token_type: if stated will get scopes of specific types only
        :return: list of dictionaries
        """
        return self.get_scopes(name=name, scope_type=token_type)

    def get_tokens_from_name(self,
                             scope_name: str,
                             token_type: str = None) -> list:
        scopes = self.get_scopes_from_name(scope_name, token_type=token_type)
        ret = []
        for scope in scopes:
            ret.append(scope['token'])

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.GLOBAL])
    def get_organizations(self,
                          name: str = None,
                          token: str = None) -> list:
        """
        Get all organizations under global organization
        :param name: filter by name
        :param token: filter by token
        :return: list of organization
        :rtype: list
        """
        ret = self.get_scopes(name=name, token=token, scope_type=ScopeTypes.ORGANIZATION)

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_products(self,
                     name: str = None,
                     token: str = None,
                     sort_by: str = None) -> list:
        """
        Retrieves all products of org
        :param name: filter product by name
        :param token:
        :param sort_by: Sort returned list
        :return: list of products
        :rtype list
        """
        products = self._generic_get(get_type="ProductVitals")['productVitals']
        products = self._enrich_products(products)
        products = self.sort_and_filter_scopes(scopes=products,
                                               name=name,
                                               token=token,
                                               sort_by=sort_by)
        return products

    def get_projects(self,
                     name: str = None,
                     token: str = None,
                     product_token: str = None,
                     product_name: str = None,
                     sort_by: str = None,
                     include_prod_proj_names: bool = True) -> list:
        """
        Retrieves products of the calling scope (org or product)
        :param name: filter returned scopes by name
        :param token:
        :param product_token: if stated retrieves projects of specific product token. If left blank retrieves all the projects in the org
        :param product_name: if stated retrieves projects of specific product name. If left blank retrieves all the projects in the org
        :param sort_by: Sort returned list
        :param include_prod_proj_names:
        :return: list of projects
        :rtype list
        """
        def _get_projects_from_products(prods: list):
            def _enrich_projects(prod_proj: dict, prod: dict):
                for proj in prod_proj:
                    proj['product_name'] = prod['name']
                    proj['productToken'] = prod['token']             # TODO REMOVE AFTER VALIDATION
                    proj['product_token'] = prod['token']
                    proj['product_creation_date'] = prod['creationDate']
                    proj['product_last_update_date'] = prod['lastUpdatedDate']

                return prod_proj

            all_projects = []
            for p in prods:
                prod_projects = self._generic_get(get_type="ProjectVitals",
                                                  kv_dict={TOKEN_TYPES_MAPPING[ScopeTypes.PRODUCT]: p['token']},
                                                  token_type='product')['projectVitals']
                prod_projects = _enrich_projects(prod_projects, p)
                all_projects.extend(prod_projects)

            self.scope_contains.add(ScopeTypes.PROJECT)

            return all_projects

        if include_prod_proj_names and self.token_type == ScopeTypes.ORGANIZATION:
            products = self._generic_get(get_type="ProductVitals")['productVitals']
            projects = _get_projects_from_products(products)
        else:
            projects = self._generic_get(get_type="ProjectVitals")['projectVitals']

        for project in projects:
            project['type'] = ScopeTypes.PROJECT
            project[TOKEN_TYPES_MAPPING[self.token_type]] = self.token
            if project.get('lastScanComment'):  # in case of comments trying to restore into dict of: k1:v1;k2:v2...
                project['project_metadata_d'] = dict([kv.split(':', 1) for kv in project['lastScanComment'].split(';') if ':' in kv])

        projects = self.sort_and_filter_scopes(scopes=projects,
                                               name=name,
                                               token=token,
                                               product_token=product_token,
                                               product_name=product_name,
                                               sort_by=sort_by)
        self.scope_contains.add(ScopeTypes.PROJECT)

        return projects

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_vulnerability(self,
                          status: str = None,  # "Active", "Ignored", "Resolved"
                          container: bool = False,
                          cluster: bool = False,
                          report: bool = False,
                          token: str = None,
                          asyncr: bool = False,
                          vulnerability_names: Union[str, list] = None) -> Union[list, bytes]:

        def get_cvss31(cvss3_score: str):
            cvss31_severity = None
            for severity in CVS31Severity.SEVERITIES.value:
                if cvss3_score and float(cvss3_score) >= severity:
                    cvss31_severity = CVS31Severity(severity).name
                    break

            return cvss31_severity

        def enrich_report(ret, vulnerability_names):
            if isinstance(ret, dict):
                ret = ret.get('vulnerabilities')
                for vul in ret:
                    vul['cvss31_severity'] = get_cvss31(vul.get('cvss3_score'))
                if isinstance(vulnerability_names, str):
                    vulnerability_names = [vulnerability_names]
                if vulnerability_names:
                    ret = [x for x in ret if x['name'] in vulnerability_names]

            return ret

        name = "Vulnerability Report"
        """
        Retrieves scope vulnerabilities. Default is "Open" If status not not set.   
        :param status: str Alert status: "Active", "Ignored", "Resolved"
        :param container:
        :param cluster:
        :param report:
        :param token: The token that the request will be created on
        :param vulnerability_names: Filter by vulnerability. Can be single string: CVE-2020-1234 or a list: [CVE-2020-1234, CVE-2020-5678]
        :return: list or xlsx if report is True
        :rtype: list or bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if not report:
            kv_dict["format"] = self.resp_format
        if status in AlertStatus.ALERT_STATUSES:
            kv_dict['status'] = status
        ret = None

        if report and vulnerability_names:
            logger.error(f"Unable to filter by the vulnerability in {name} while running with Excel format. Please use JSON output format")
        elif container:
            if token_type == ScopeTypes.ORGANIZATION:
                logger.debug(f"Running Container {name}")
                ret = self._generic_get(get_type='ContainerVulnerabilityReportRequest', token_type=token_type, kv_dict=kv_dict)
            else:
                logger.error(f"Container {name} is unsupported on {token_type}")
        elif cluster:
            if token_type == ScopeTypes.PRODUCT:
                logger.debug(f"Running Cluster {name}")
                ret = self._generic_get(get_type='ClusterVulnerabilityReportRequest', token_type="", kv_dict=kv_dict)
            else:
                logger.error(f"Cluster {name} is unsupported on {token_type}")
        elif asyncr:
            kv_dict['reportType'] = f"{token_type.capitalize()}VulnerabilityReport"
            ret = self.async_report_generation(token_type, kv_dict, report)
        else:
            logger.debug(f"Running {name}")
            ret = self._generic_get(get_type='VulnerabilityReport', token_type=token_type, kv_dict=kv_dict)

        if ret and isinstance(ret, dict):
            for key, value in ret.items():
                if 'asyncReport' in key:
                    ret[key] = enrich_report(value, vulnerability_names)
                elif 'Failed' not in key:
                    ret = enrich_report(ret, vulnerability_names)

        return ret

    def async_report_generation(self, token_type, kv_dict, report):
        self.token_type = token_type
        kv_dict["format"] = "xlsx" if report else "json"
        logger.debug(f"Running generate{token_type.capitalize()}ReportAsync")
        ret = self.call_ws_api(request_type=f"generate{token_type.capitalize()}ReportAsync", kv_dict=kv_dict)
        report_status_uuid = ret.get('asyncProcessStatus').get('uuid')
        request_status = None
        kv_dict_org = {}
        time_sleeped = 0
        dict_ret = {}
        while 'IN_PROGRESS' or None or 'PENDING' in request_status:
            time.sleep(2)
            time_sleeped += 1
            self.token_type = ScopeTypes.ORGANIZATION
            kv_dict_org['orgToken'] = self.token
            kv_dict_org.update({'uuid': report_status_uuid})
            logger.debug(f"Running getAsyncProcessStatus")
            ret = self.call_ws_api(request_type=f"getAsyncProcessStatus", kv_dict=kv_dict_org)
            request_status = ret.get('asyncProcessStatus').get('status')
            if 'SUCCESS' in request_status:
                kv_dict_org.update({'reportStatusUUID': report_status_uuid})
                logger.info(f"Downloading Async report, report status id : {report_status_uuid}")
                response = self.call_ws_api(request_type=f"downloadAsyncReport", kv_dict=kv_dict_org)
                try:
                    zfile = zipfile.ZipFile(io.BytesIO(response))
                    for file in zfile.filelist:
                        file_name = file.filename
                        if file_name.endswith(("json")):
                            output = json.loads(zfile.read(file_name))
                        if file_name.endswith("xlsx"):
                            output = zfile.read(file_name)
                        dict_ret['asyncReport: ' + file_name] = output
                except Exception as e:
                    dict_ret['Failed'] = f'report status id : {report_status_uuid}'
                    logger.error(e)
                    break
                break
            elif 'FALILED' in request_status or time_sleeped >= 180:
                dict_ret['Failed'] = f'report status id : {report_status_uuid}'
                logger.error(f"Report is too big on {token_type} token: {kv_dict['productToken']}."
                             f"Try to pull manually using your orgToken, userKey and the reportStatusUUID: {report_status_uuid}")
                break
            else:
                continue
        return dict_ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.ORGANIZATION])
    def get_container_vulnerability(self,
                                    report: bool = False,
                                    token: str = None,
                                    asyncr: bool = False) -> bytes:
        return self.get_vulnerability(container=True, report=report, token=token)

    def get_vulnerabilities_per_lib(self,
                                    token: str = None) -> list:
        def __get_highest_severity__(comp_severity, severity):
            sev_dict = {"high": 3, "medium": 2, "low": 1, "none": 0}

            return comp_severity if sev_dict[comp_severity] > sev_dict[severity] else severity

        vuls = self.get_vulnerability(token=token)
        logger.debug(f"Found {len(vuls)} Vulnerabilities")
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
        logger.debug(f"Found {len(libs_vul)} libraries with vulnerabilities")

        return list(libs_vul.values())

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_change_log(self,
                       start_date: datetime = None) -> list:
        name = "Change Log Report"
        if start_date is None:
            kv_dict = None
        else:
            kv_dict = {'startDateTime': start_date.strftime("%Y-%m-%d %H:%M:%S")}
        logger.debug(f"Running {name}")

        return self._generic_get(get_type="ChangesReport", token_type="", kv_dict=kv_dict)['changes']

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

        def __fix_spdx_license__(lic: dict) -> None:
            if not lic.get('spdxName'):
                if lic.get('name') == "Public Domain":
                    lic['spdxName'] = "CC-PDDC"
                elif lic.get('name').find("AGPL-1.0") > -1 :
                    if lic.get('name') == "AGPL-1.0":
                        lic['spdxName'] = "AGPL-1.0-only"
                    else:
                        lic['spdxName'] = "AGPL-1.0-or-later"
                elif lic.get('name').find("AGPL-3.0") > -1 :
                    if lic.get('name') == "AGPL-3.0":
                        lic['spdxName'] = "AGPL-3.0-only"
                    else:
                        lic['spdxName'] = "AGPL-3.0-or-later"
                elif lic.get('name').find("GPL-1.0") > -1 :
                    if lic.get('name') == "GPL-1.0":
                        lic['spdxName'] = "GPL-1.0-only"
                    else:
                        lic['spdxName'] = "GPL-1.0-or-later"
                elif lic.get('name').find("GPL-2.0") > -1 :
                    if lic.get('name') == "GPL-2.0":
                        lic['spdxName'] = "GPL-2.0-only"
                    else:
                        lic['spdxName'] = "GPL-2.0-or-later"
                elif lic.get('name').find("GPL-3.0") > -1 :
                    if lic.get('name') == "GPL-3.0":
                        lic['spdxName'] = "GPL-3.0-only"
                    else:
                        lic['spdxName'] = "GPL-3.0-or-later"
                elif lic.get('name').find("LGPL-1.0") > -1 :
                    if lic.get('name') == "LGPL-1.0":
                        lic['spdxName'] = "LGPL-1.0-only"
                    else:
                        lic['spdxName'] = "LGPL-1.0-or-later"
                elif lic.get('name').find("LGPL-2.0") > -1 :
                    if lic.get('name') == "LGPL-2.0":
                        lic['spdxName'] = "LGPL-2.0-only"
                    else:
                        lic['spdxName'] = "LGPL-2.0-or-later"
                elif lic.get('name').find("LGPL-2.1") > -1:
                    if lic.get('name') == "LGPL-2.1":
                        lic['spdxName'] = "LGPL-2.1-only"
                    else:
                        lic['spdxName'] = "LGPL-2.1-or-later"
                elif lic.get('name').find("LGPL-3.0") > -1 :
                    if lic.get('name') == "LGPL-3.0":
                        lic['spdxName'] = "LGPL-3.0-only"
                    else:
                        lic['spdxName'] = "LGPL-3.0-or-later"
                elif lic.get('name') == "BSD Zero":
                    lic['spdxName'] = "0BSD"
                elif lic.get('name') == "Unlicense":
                    lic['spdxName'] = "Unlicense"
                elif lic.get('name') == "Tcl-Tk":
                    lic['spdxName'] = "TCL"
                if lic.get('spdxName'):
                    logger.info(f"Fixed spdxName of {lic['name']} to {lic['spdxName']}")
                else:
                    logger.warning(f"Unable to fix spdxName of {lic['name']}")

        def _enrich_lib(library: dict, spdx: dict):
            for lic in library.get('licenses'):
                __fix_spdx_license__(lic)                                        # Manually fixing this license
                try:
                    lic['spdx_license_dict'] = spdx[lic['spdxName']]
                    logger.debug(f"Found license: {lic['spdx_license_dict']['licenseId']}")
                except KeyError:
                    logger.warning(f"License with identifier: {lic['name']} was not found")

        report_name = 'licenses'
        token_type, kv_dict = self.set_token_in_body(token)
        if histogram:
            logger.debug(f"Running {token_type} {report_name} Histogram")
            ret = self._generic_get(get_type='LicenseHistogram', token_type=token_type, kv_dict=kv_dict)['licenseHistogram']
        else:
            logger.debug(f"Running {token_type} {report_name}")
            kv_dict['excludeProjectOccurrences'] = exclude_project_occurrences
            ret = self._generic_get(get_type='Licenses', token_type=token_type, kv_dict=kv_dict)['libraries']

            if full_spdx:
                for lib in ret:
                    _enrich_lib(lib, self.spdx_lic_dict)

        return ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_source_files(self,
                         token: str = None,
                         report: bool = False,
                         asyncr: bool = False) -> Union[list, bytes]:
        report_name = 'Source File Inventory Report'
        token_type, kv_dict = self.set_token_in_body(token)
        if report:
            kv_dict["format"] = "xlsx"
            logger.debug(f"Running {token_type} {report_name}")
        else:
            kv_dict["format"] = "json"
            logger.debug(f"Running {token_type} Inventory")
        ret = self._generic_get(get_type='SourceFileInventoryReport', token_type=token_type, kv_dict=kv_dict)
        if isinstance(ret, dict):
            ret = ret['sourceFiles']
            for src_file in ret:
                src_file['lib_version'] = ws_utilities.parse_filename_to_gav(src_file['library'].get('version'))

        return ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_source_file_inventory(self,
                                  report: bool = True,
                                  token: str = None,
                                  asyncr: bool = False) -> bytes:
        """
        :param asyncr: get output using async API call
        :param report: get output as xlsx if True
        :param token: The token that the request will be created on
        :return: list or bytes(xlsx) or dict(paginated reports when asyncr)
        :rtype: list or bytes or dict
        """
        return self.get_source_files(token=token, report=report, asyncr=False)

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_in_house_libraries(self,
                               report: bool = False,
                               token: str = None,
                               asyncr: bool = False) -> Union[list, bytes]:
        """
        :param asyncr: get output using async API call
        :param report: get output as xlsx if True
        :param token: The token that the request will be created on
        :return: list or bytes(xlsx) or dict(paginated reports when asyncr)
        :rtype: list or bytes or dict
        """
        report_name = 'In-House Libraries'
        token_type, kv_dict = self.set_token_in_body(token)
        if report:
            logger.debug(f"Running {token_type} {report_name} Report")
            ret = self._generic_get(get_type='InHouseReport', token_type=token_type, kv_dict=kv_dict)
        else:
            logger.debug(f"Running {token_type} {report_name}")
            ret = self._generic_get(get_type='InHouseLibraries', token_type=token_type, kv_dict=kv_dict)['libraries']

        return ret['sourceFiles'] if isinstance(ret, dict) else ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_in_house(self,
                     report: bool = True,
                     token: str = None,
                     asyncr: bool = False) -> bytes:
        return self.get_in_house_libraries(report=report, token=token, asyncr=False)

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_users(self,
                  name: str = None,
                  email: str = None) -> list:
        """
        Get organization users
        :param name: filter list by user name
        :param email:  filter list by user email
        :return: list of users
        """
        logger.debug(f"Getting users of the organization")
        ret = self._generic_get(get_type='AllUsers', token_type="")['users']
        for user in ret:
            user['org_token'] = self.token

        if name:
            ret = [user for user in ret if user.get('name') == name]
        if email:
            ret = [user for user in ret if user.get('email') == email]

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_user(self,
                 name: str = None,
                 email: str = None) -> dict:
        """
        Return user data
        :param name: filter by user name
        :param email: filter by user email
        :return: dictionary with user's details
        :rtype: dict
        """
        if not name and not email:
            logger.error("Specifying name or email is mandatory")
        else:
            logger.debug(f"Getting user data: {name if name else email}")
            user_list = self.get_users(name=name, email=email)

            return user_list.pop() if user_list else None

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_group(self,
                  group_name: str) -> dict:
        ret = self.get_groups(name=group_name)
        if ret:
            return ret[0]
        else:
            raise WsSdkServerMissingGroupError(group_name)

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_users_in_group(self,
                           group_name: str) -> dict:
        ret = self.get_group(group_name=group_name)['users']
        for user in ret:
            user['org_token'] = self.token

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
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
        logger.debug("Getting Organization groups")
        ret = self._generic_get(get_type="AllGroups", token_type="")['groups']
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
        if token_type == ScopeTypes.PROJECT:
            logger.error(f"{report_name} is unsupported on project")
        else:
            logger.debug(f"Running {token_type} Assignment")
            assignments = self._generic_get(get_type='Assignments', token_type=token_type, kv_dict=kv_dict)
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
                    logger.debug(f"No roles were found under: {ent[1]}")

            if entity_type in ENTITY_TYPES.keys():
                logger.debug(f"Filtering assignments by entity type: {entity_type}")
                ret_assignments = [asc for asc in ret_assignments if asc['ent_type'] == entity_type[:-1]]

            if role_type in RoleTypes.ROLE_TYPES:
                logger.debug(f"Filtering assignments by role type: {role_type}")
                ret_assignments = [asc for asc in ret_assignments if asc['role_type'] == role_type]

        return ret_assignments

    @Decorators.report_metadata(report_bin_type="pdf", report_scope_types=[ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_risk(self,
                 token: str = None,
                 report: bool = True,
                 asyncr: bool = False) -> bytes:
        """API for WhiteSource
        :token: Token of scope
        :token_type: Scope Type (organization, product, project)
        :return bytes (pdf)
        :rtype: bytes
        """
        report_name = "Risk Report"
        token_type, kv_dict = self.set_token_in_body(token)
        if not report:
            logger.error(f"Report {report_name} is supported in pdf format. (set report=True)")
        elif token_type == ScopeTypes.PROJECT:
            logger.error(f"{report_name} is unsupported on project")
        else:
            logger.debug(f"Running {report_name} on {token_type}")
            return self._generic_get(get_type='RiskReport', token_type=token_type, kv_dict=kv_dict)

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_library_location(self,
                             token: str = None,
                             report: bool = False,
                             asyncr: bool = False) -> Union[list, bytes]:
        report_name = "Library Location"
        """
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if report and token_type == ScopeTypes.PROJECT:
            logger.error(f"{report_name} report is unsupported on {token_type}")
        elif report:
            logger.debug(f"Running {report_name} report on {token_type}")
            ret = self._generic_get(get_type='LibraryLocationReport', token_type=token_type, kv_dict=kv_dict)
        elif not report and token_type == ScopeTypes.ORGANIZATION:
            logger.error(f"{report_name} is unsupported on {token_type}")
            ret = None
        else:
            logger.debug(f"Running {report_name} on {token_type}")
            ret = self._generic_get(get_type='LibraryLocations', token_type=token_type, kv_dict=kv_dict)

        return ret['libraryLocations'] if isinstance(ret, dict) else ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT])
    def get_license_compatibility(self,
                                  token: str = None,
                                  report: bool = False,
                                  asyncr: bool = False) -> bytes:
        report_name = "License Compatibility Report"
        """
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if not report:
            logger.error(f"{report_name} is supported in xlsx format. (set report=True)")
        elif token_type == ScopeTypes.ORGANIZATION:
            logger.error(f"{report_name} is unsupported on organization level")
        else:
            logger.debug(f"Running {report_name} on {token_type}")
            return self._generic_get(get_type='LicenseCompatibilityReport', token_type=token_type, kv_dict=kv_dict)

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_due_diligence(self,
                          token: str = None,
                          report: bool = False,
                          asyncr: bool = False) -> Union[list, bytes]:
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
        logger.debug(f"Running {report_name} on {token_type}")
        ret = self._generic_get(get_type='DueDiligenceReport', token_type=token_type, kv_dict=kv_dict)

        return ret['licenses'] if isinstance(ret, dict) else ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_attributes(self,
                       token: str = None,
                       asyncr: bool = False) -> bytes:
        """
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        report_name = "Attributes Report"
        token_type, kv_dict = self.set_token_in_body(token)
        if token_type == ScopeTypes.PROJECT:
            logger.error(f"{report_name} is unsupported on project")
        else:
            logger.debug(f"Running {token_type} {report_name}")
            return self._generic_get(get_type='AttributesReport', token_type=token_type, kv_dict=kv_dict)

    @Decorators.report_metadata(report_bin_type=["html", 'txt'], report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT])
    def get_attribution(self,
                        token: str,
                        reporting_aggregation_mode: str = "BY_PROJECT",
                        report: bool = False,
                        report_header: str = None,
                        report_title: str = None,
                        report_footer: str = None,
                        reporting_scope: str = None,
                        missing_license_display_option: str = "BLANK",
                        export_format: str = "json",
                        license_reference_text_placement: str = "LICENSE_SECTION",
                        custom_attribute: str = None,
                        include_versions: str = True,
                        asyncr: bool = False) -> Union[dict, bytes]:
        """
        Method that creates Inventory like response with custom attributed and notice text/reference data
        :param reporting_aggregation_mode:
        :param token:
        :param report:
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
        name = "Attribution Report"
        ret = None
        token_type, kv_dict = self.set_token_in_body(token)

        if token_type == ScopeTypes.ORGANIZATION:
            logger.error(f"{name} is unsupported on organization")
        elif reporting_aggregation_mode not in ['BY_COMPONENT', 'BY_PROJECT']:
            logger.error(f"{name} incorrect reporting_aggregation_mode value. Supported: BY_COMPONENT or BY_PROJECT")
        elif missing_license_display_option not in ['BLANK', 'GENERIC_LICENSE']:
            logger.error(f"{name} missing_license_display_option value. Supported: BLANK or GENERIC_LICENSE")
        elif report and export_format == "JSON":
            logger.error(f"{name} only JSON is supported in non report mode")
        elif report and export_format not in ['TXT', 'HTML']:
            logger.error(f"{name} incorrect export_format value. Supported: TXT, HTML or JSON")
        elif reporting_scope not in [None, 'SUMMARY', 'LICENSES', 'COPYRIGHTS', 'NOTICES', 'PRIMARY_ATTRIBUTES']:
            logger.error(f"{name} incorrect reporting scope value. Supported: SUMMARY, LICENSES, COPYRIGHTS, NOTICES or PRIMARY_ATTRIBUTES")
        elif license_reference_text_placement not in ['LICENSE_SECTION', 'APPENDIX_SECTION']:
            logger.error(f"{name} incorrect license_reference_text_placement value. Supported: LICENSE_SECTION or APPENDIX_SECTION  ")
        else:
            if report_header:
                kv_dict['reportHeader'] = report_header
            if report_title:
                kv_dict['reportTitle'] = report_title
            if report_footer:
                kv_dict['reportFooter'] = report_footer
            if reporting_scope:
                kv_dict['reportingScope'] = reporting_scope
            if custom_attribute:
                kv_dict['customAttribute'] = custom_attribute

            kv_dict['reportingAggregationMode'] = reporting_aggregation_mode
            kv_dict['missingLicenseDisplayOption'] = missing_license_display_option
            kv_dict['exportFormat'] = export_format
            kv_dict['licenseReferenceTextPlacement'] = license_reference_text_placement
            kv_dict['includeVersions'] = str(include_versions)
            logger.debug(f"Running {token_type} {name}")

            ret = self._generic_get(get_type='AttributionReport', token_type=token_type, kv_dict=kv_dict)

        return ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_effective_licenses(self,
                               report: bool = True,
                               token: str = None,
                               asyncr: bool = False) -> bytes:
        """
        :param report:
        :param token: The token that the request will be created on
        :return: bytes (xlsx)
        :rtype bytes
        """
        report_name = 'Effective Licenses Report'
        token_type, kv_dict = self.set_token_in_body(token)
        if token_type == ScopeTypes.PROJECT:
            logger.error(f"{report_name} is unsupported on project")
        elif not report:
            logger.error(f"{report_name} is only supported on binary format")
        else:
            logger.debug(f"Running {token_type} {report_name}")
            return self._generic_get(get_type='EffectiveLicensesReport', token_type=token_type, kv_dict=kv_dict)

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_bugs(self,
                 report: bool = True,
                 token: str = None,
                 asyncr: bool = False) -> bytes:
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
            logger.debug(f"Running {token_type} {report_name}")

            ret = self._generic_get(get_type='BugsReport', token_type=token_type, kv_dict=kv_dict)
        else:
            logger.error(f"{report_name} is only supported as xls (set report=True")

        return ret

    @Decorators.report_metadata(report_bin_type="xlsx", report_scope_types=[ScopeTypes.PROJECT, ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
    def get_request_history(self,
                            plugin: bool = False,
                            report: bool = True,
                            token: str = None,
                            asyncr: bool = False) -> bytes:
        """
        :param asyncr: Get report by an asynchronous API call
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
            logger.error(f"{report_name} is only supported as xlsx (set report=True)")
        elif report and plugin and token_type == ScopeTypes.ORGANIZATION:
            if asyncr:
                logger.debug(f"Running asynchronous PluginRequestHistoryReport on {token_type} ")
                kv_dict['reportType'] = f"PluginRequestHistoryReport"
                ret = self.async_report_generation(token_type, kv_dict, report)
            else:
                ret = self.call_ws_api(request_type='getPluginRequestHistoryReport', kv_dict=kv_dict)
        elif plugin:
            logger.error(f"Plugin {report_name} is unsupported for {token_type}")
        elif asyncr:
            logger.error(f"Asynchronous {report_name} is unsupported")
        else:
            logger.debug(f"Running {token_type} {report_name}")
            ret = self._generic_get(get_type='RequestHistoryReport', token_type=token_type, kv_dict=kv_dict)

        return ret

    def get_product_of_project(self,
                               token: str) -> dict:
        project_scope = self.get_scope_by_token(token=token)
        if project_scope['type'] == ScopeTypes.PROJECT:
            return self.get_scope_by_token(token=project_scope[TOKEN_TYPES_MAPPING[ScopeTypes.PRODUCT]])

    def get_project(self,
                    token: str) -> dict:
        all_projects = self.get_projects()
        for project in all_projects:
            if project['token'] == token:
                return project
        logger.error(f"Project with token: {token} was not found")
        raise WsSdkServerMissingTokenError(token, ScopeTypes.PROJECT)

    def get_project_metadata(self,
                             token: str) -> dict:
        """
        Method to return metadata dictionary base on project's scan comment
        :param token:
        :return:
        """
        project = self.get_project(token=token)

        return project['project_metadata_d']

    def get_tags(self,
                 token: str = None) -> list:
        report_name = "Tags"
        token_type, kv_dict = self.set_token_in_body(token)

        if token and token_type == ScopeTypes.PROJECT or self.token_type == ScopeTypes.PROJECT:                              # getProjectTags
            ret = self._generic_get(get_type="ProjectTags", token_type="", kv_dict=kv_dict)['projectTags']
        elif token and token_type == ScopeTypes.PRODUCT or self.token_type == ScopeTypes.PRODUCT:                            # getProductTags
            ret = self._generic_get(get_type="ProductTags", token_type="", kv_dict=kv_dict)['productTags']
        # Cases where no Token is specified
        elif not token and token_type == ScopeTypes.ORGANIZATION:
            product_tags = self._generic_get(get_type="ProductTags", token_type=self.token_type, kv_dict=kv_dict)['productTags'] # getOrganizationProductTags
            for prod in product_tags:
                prod['type'] = ScopeTypes.PRODUCT
            project_tags = self._generic_get(get_type="ProjectTags", token_type=self.token_type, kv_dict=kv_dict)['projectTags']  # getOrganizationProductTags
            for prod in product_tags:
                prod['type'] = ScopeTypes.PROJECT
            ret = product_tags + project_tags
        elif not token and token_type == ScopeTypes.PRODUCT:
            ret = self._generic_get(get_type="ProjectTags", token_type=self.token_type, kv_dict=kv_dict)['projectTags'] # getProductProjectTags
        logger.debug(f"Getting {report_name} on {token_type} token: {token}")

        return ret

    def delete_scope(self,
                     token: str,
                     project: dict = None) -> dict:
        """
        :param project:
        :param token: token of entity to delete (product or project)
        :return: dict whether succeeded.
        :rtype dict
        """
        token_type, kv_dict = self.set_token_in_body(token)
        if not project:
            project = self.get_project(token)
            project_name = self.get_scope_name_by_token(token)
        else:
            project_name = project.get('name')
        if token_type == ScopeTypes.PROJECT:
            kv_dict[TOKEN_TYPES_MAPPING[ScopeTypes.PRODUCT]] = project[TOKEN_TYPES_MAPPING[ScopeTypes.PRODUCT]]
        logger.debug(f"Deleting {token_type}: {project_name} Token: {token}")

        return self.call_ws_api(request_type=f"delete{token_type.capitalize()}", kv_dict=kv_dict)

    def get_libraries(self,
                      search_value: str,
                      version: str = None,
                      search_only_name: bool = False,
                      global_search: bool = True) -> list:
        """
        Method to search for libraries in WS Database (Highly inefficient and inaccurate as max 100 results returns)
        :param search_only_name: Specify to return results that match the exact name
        :param version: Optional version of the searched library.
        :param search_value: Search string to search. Acts like "contains" i.e. search for all libraries that contains the string.
        :param global_search: whether to search global database.
        :return:
        """
        if global_search:
            if version:
                search_value += f"-{version}"
            logger.debug(f"Performing Global Search with value: \'{search_value}\'")
            libs = self.call_ws_api(request_type="librarySearch", kv_dict={"searchValue": search_value}).get('libraries')

            if version:
                libs = [lib for lib in libs if lib.get('version') == version]

            if search_only_name:
                logger.debug(f"Filtering search results of search value \'{search_value}\' by exact name")
                libs = [lib for lib in libs if lib.get('name') == search_value]
            logger.info(f"Global search found {len(libs)} results for search value: \'{search_value}\'")
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
            logger.debug(f"Replacing \"Source Library\" Type with {languages[0]}")
            lib_type = languages[0]

        if lib_type in LibTypes.type_to_lib_t.keys():
            logger.debug(f"Replacing {lib_type} Type with {LibTypes.type_to_lib_t[lib_type]}")
            lib_type = LibTypes.type_to_lib_t[lib_type]

        kv_dict = {}
        local_vars = locals()                                    # Iterating method variables to set search values
        for val in search_values.items():
            if local_vars[val[0]] is not None:
                kv_dict[val[1]] = local_vars[val[0]]
        ret = self._generic_get(get_type="LibraryInfo", token_type="", kv_dict=kv_dict).get('librariesInformation')

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
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
            logger.error("At least 1 alert uuid must be provided")
        elif status not in AlertStatus.ALERT_SET_STATUSES:
            logger.error(f'{status} status is invalid. Must be "Ignored" or "Active"')
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
                    logger.debug(f"No JSON to decode: {c_d.get('text')}")
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
                    logger.debug(f"Skipping notice line: {lines[i]}")
                elif lines[i].startswith('Reference:'):
                    curr_dict['reference'] = lines[i].replace('Reference:', "")
                else:
                    curr_dict['text'] = curr_dict.get('text', "") + lines[i]
            __append_notice_text_as_json__(curr_dict)

            return ret_list

        token_type, kv_dict = self.set_token_in_body(token=product_token)

        if token_type == ScopeTypes.PRODUCT:
            ret = self._generic_get(get_type='NoticesTextFile', token_type="", kv_dict=kv_dict)
        else:
            raise WsSdkServerTokenTypeError(product_token)

        return ret if as_text else __convert_notice_text_to_json__(ret)

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
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
        logger.debug(f"Running {token_type} {report_name}")
        kv_dict['aggregatePolicies'] = include_parent_policy
        ret = self._generic_get(get_type='Policies', token_type=token_type, kv_dict=kv_dict)['policies']
        pol_ctx2scope = {'DOMAIN': ScopeTypes.ORGANIZATION,
                         'PRODUCT': ScopeTypes.PRODUCT,
                         'PROJECT': ScopeTypes.PROJECT}

        for pol in ret:
            pol['scope_type'] = pol_ctx2scope[pol['policyContext']]

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def create_user(self,
                    name: str,
                    email: str = None,
                    inviter_email: str = None,
                    is_service: bool = False,
                    add_to_web_advisor: bool = False) -> dict:
        """
        Create user or service user
        :param name: name of created user - if user exists, the method will fail. Server add mail server to the name value (i.e. name: "X" and email "Y.tld" => WS user name: "X Y"
        :param email: email of the invitee
        :param inviter_email:
        :param is_service: Whether to create a service user (inviter_email and email is not required. # Space is not allowed in name (I think because email address is auto generated and does not replace the space)
        :param add_to_web_advisor: Whether to add use to Web Advisor (Not applicable for service user)
        :returns None if User, User Key if Service User
        :rtype: str None
        """
        token_type, kv_dict = self.set_token_in_body()
        ret = {}
        user_exists = False
        if self.get_users(name=name):                       # createUser WILL THROW AN ERROR IF CALLED ON EXISTING USER
            logger.warning(f"User: {name} already exists")
            user_exists = True
        elif is_service:
            if " " in name:
                logger.error("Spaces in a service name are not allowed")
            else:
                logger.debug(f"Creating Service User: {name}")
                kv_dict['addedUser'] = {"name": name}
                ret = self.call_ws_api(request_type='createServiceUser', kv_dict=kv_dict).get('userToken')
        elif email and inviter_email:
            logger.debug(f"Creating User: {name} email : {email} with Inviter email: {inviter_email}")
            kv_dict['inviter'] = {"email": inviter_email}
            kv_dict['addedUser'] = {"name": name, "email": email}
            ret = self.call_ws_api(request_type='createUser', kv_dict=kv_dict)
            user_exists = True
        elif not email:
            logger.error("Missing user email to create User")
        elif not inviter_email:
            logger.error("Missing Inviter email to create User")

        if add_to_web_advisor and email:
            logger.debug(f"Inviting user's email {email} to Web Advisor")
            self.invite_user_to_web_advisor(user_email=email)

        return ret                                              #  TODO BUG IN CONFLUENCE DOCUMENTATION (userToken)

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION, ScopeTypes.GLOBAL])
    def delete_user(self,
                    email: str,
                    org_token: str = None) -> dict:
        """
        Remove user from organization by email address, If run by global and org_token is not None it will remove from
        a specific token and if not will remove from all organizations under global
        :param email: User's email to remove
        :param org_token: Delete from a specific org when running as Global administrator
        """
        if self.token_type == ScopeTypes.GLOBAL:
            orgs = self.get_organizations(token=org_token) if org_token else self.get_organizations()
            if orgs:
                for org in orgs:
                    temp_conn = copy(self)                      # TODO MAKE THIS GENERIC
                    temp_conn.token = org['token']
                    temp_conn.token_type = ScopeTypes.ORGANIZATION
                    temp_conn.delete_user(email)
            else:
                logger.error(f"Organization token: {org_token} was not found under Global Organization: {self.token}")
        else:
            if not self.get_users(email=email):
                logger.error(f"User's email: {email} does not exist in the organization")
            else:
                logger.debug(f"Deleting user email: {email} from Organization Token: {self.token}")
                return self.call_ws_api(request_type="removeUserFromOrganization", kv_dict={"user": {"email": email}})

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def create_group(self,
                     name: str,
                     description: str = None) -> dict:
        token_type, kv_dict = self.set_token_in_body()
        kv_dict['group'] = {"name": name,
                            "description": name if description is None else description,
                            }
        ret = {}
        if self.get_groups(name=name):
            logger.warning(f"Group: \'{name}\' already exists")
        else:
            logger.debug(f"Creating Group: {name}")
            ret = self.call_ws_api(request_type='createGroup', kv_dict=kv_dict)

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def create_product(self,
                       name: str):

        return self.call_ws_api(request_type="createProduct", kv_dict={"productName": name})

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION, ScopeTypes.PRODUCT])
    def create_project(self,
                       name: str,
                       product_token: str = None,
                       product_name: str = None):
        ret = None
        if product_token and product_name:
            logger.error(f"Unable to create project: '{name}'. Only project token or project name is allowed")
        elif ScopeTypes.ORGANIZATION and (product_token is None and product_name is None):
            logger.error(f"Unable to create project: '{name}'. Missing product value")
        else:
            if product_name:
                product_token = self.get_tokens_from_name(product_name, token_type=ScopeTypes.PRODUCT)
            if product_token:
                token_type, kv_dict = self.set_token_in_body(product_token[0])
                kv_dict['projectName'] = name
                ret = self.call_ws_api(request_type="createProject", kv_dict=kv_dict)
            else:
                logger.error(f"Unable to create project: '{name}'. Product name: '{product_name}' was not found")

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def assign_user_to_group(self,
                             user_email: str,
                             group_name: str) -> dict:
        if not self.get_groups(name=group_name):
            logger.error(f"Unable to assign user: {user_email} to Group: {group_name}. Group does not exist")
        elif not self.get_users(email=user_email):
            logger.error(f"User's Email: {user_email} does not exist")
        elif self.get_groups(name=group_name, user_email=user_email):
            logger.warning(f"User's Email: {user_email} already in group: {group_name}")
        else:
            logger.debug(f"Assigning user's Email: {user_email} to Group: {group_name}")
            token_type, kv_dict = self.set_token_in_body()
            kv_dict['assignedUsers'] = [
                [{'name': group_name},
                 [{"email": user_email}]
                 ]
            ]

            return self.call_ws_api(request_type='addUsersToGroups', kv_dict=kv_dict)

    @Decorators.check_permission(permissions=[ScopeTypes.PRODUCT, ScopeTypes.ORGANIZATION])
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
            logger.error("At least 1 user or group is required")
        elif token_type is ScopeTypes.ORGANIZATION and role_type not in RoleTypes.ORG_ROLE_TYPES:
            logger.error(f"Invalid {ScopeTypes.ORGANIZATION} Role type: {role_type}. Available Roles: {RoleTypes.PROD_ROLES_TYPES}")
        elif token_type is ScopeTypes.PRODUCT and role_type not in RoleTypes.PROD_ROLES_TYPES:
            logger.error(f"Invalid {ScopeTypes.PRODUCT} Role type: {role_type}. Available Roles: {RoleTypes.PROD_ROLES_TYPES}")
        else:
            all_groups_assignments = __get_assignments__(group, "name")         # Filter non-existing groups
            groups_assignments = []
            for group_item in all_groups_assignments:
                if self.get_groups(name=group_item['name']):
                    groups_assignments.append(group_item)
                else:
                    logger.warning(f"Group: {group_item} does not exist")
            groups_assignments = groups_assignments if len(groups_assignments) > 0 else None

            all_users_assignments = __get_assignments__(email, "email")          # Filter non-existing users in the org
            users_assignments = []
            for user_item in all_users_assignments:
                if self.get_users(email=user_item['email']):
                    users_assignments.append(user_item)
                else:
                    logger.warning(f"User email: {user_item['email']} does not exist")

            if users_assignments or groups_assignments:
                kv_dict[role_type] = {'userAssignments': users_assignments,
                                      'groupAssignments': groups_assignments}
                logger.debug(f"Assigning User(s): {email} Group(s): {group} to Role: {role_type}")
                return self._generic_set(set_type='Assignments', token_type=token_type, kv_dict=kv_dict)
            else:
                logger.error("No valid user or group were found")

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def invite_user_to_web_advisor(self,
                                   user_email: str):
        token_type, kv_dict = self.set_token_in_body()
        kv_dict['userEmail'] = user_email
        logger.debug(f"Inviting email: '{user_email}' to Web Advisor")

        return self.call_ws_api(request_type='inviteUserToWebAdvisor', kv_dict=kv_dict)

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def regenerate_service_user_key(self,
                                    service_user_key: str) -> str:
        """
        Regenerates service user keys
        :param service_user_key: the current service key
        :return: new service key
        :rtype str
        """
        if ws_utilities.is_token(service_user_key):
            logger.debug(f"Generating new key for service user key: {service_user_key}")
            ret = self.call_ws_api(request_type='regenerateUserKey', kv_dict={'serviceUserKey': service_user_key})['userToken']
            logger.debug(f"New token: {ret}")
        else:
            raise WsSdkTokenError(service_user_key)

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])       # TODO MISSING VALID integrationType VALS
    def get_integration_token(self,
                              integration_type: str) -> str:
        ret = None
        if integration_type in IntegrationTypes.Types:
            token_type, kv_dict = self.set_token_in_body()
            kv_dict['integrationType'] = integration_type
            logger.debug(f"Retrieving Integration Activation Token of type: {integration_type}")

            ret = self._generic_get(get_type='IntegrationActivationToken', token_type=token_type, kv_dict=kv_dict)
        else:
            logger.error(f"Invalid Integration Type: '{integration_type}'")

        return ret

    @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    def get_last_scan_process_status(self, request_token) -> str:
        """
        Returns the status of the last UA scan.
        :param request_token: value returned from the UA scan output
        :return: Possible Statuses: "UNKNOWN", "IN_PROGRESS", "UPDATED", "FINISHED", "FAILED", "SKIPPED"
        :returns: str
        """
        return self._generic_get(get_type="RequestState", token_type="", kv_dict={'requestToken': request_token})['requestState']

    # @Decorators.check_permission(permissions=[ScopeTypes.ORGANIZATION])
    # def match_policy(self, policy_obj):     # TODO TBD
    #     """
    #     TBD: Method to check a lib against policy object
    #     :param policy_obj: class that represents policy rules on lib (perhaps including alerts)
    #     :returns whether there is a match on which conditions
    #     """
    #     pass

    def change_origin_of_source_lib(self,
                                    lib_uuid: str = None,
                                    lib_name: str = None,
                                    source_files_sha1: list = [],
                                    user_comments: str = None):
        """
        Method to change source files association to a source library
        :param lib_uuid: UUID of the source library
        :param lib_name: Name of the source library
        :param source_files_sha1: list of sha1 of source files to change
        :param user_comments: Optional comments
        """
        if not source_files_sha1:
            logger.error("At least one source file sha1 is required")
        elif not (lib_uuid or lib_name):
            logger.error(f"Library UUID or Library name is required")
        else:
            if lib_name:
                lib_uuid = self.get_lib_uuid(name=lib_name)
                logger.info(f"Found library UUID: '{lib_uuid}' of library: '{lib_name}'")

            token_type, kv_dict = self.set_token_in_body()
            kv_dict['targetKeyUuid'] = lib_uuid
            kv_dict['sourceFiles'] = source_files_sha1
            kv_dict['userComments'] = user_comments
            logger.debug(f"Changing original of source library: '{lib_uuid}'")

        self.call_ws_api(request_type="changeOriginLibrary", kv_dict=kv_dict)

