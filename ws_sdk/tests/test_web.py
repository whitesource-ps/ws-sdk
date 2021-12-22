import json
from datetime import datetime
from unittest import TestCase
from mock import patch
import logging

import ws_sdk.web
from ws_sdk.ws_constants import *
from ws_sdk.web import WS
from ws_sdk.ws_errors import *

logger = logging.getLogger(__name__)
ws_sdk_web = logging.getLogger(ws_sdk.web.WS.__module__)
ws_sdk_web.setLevel(logging.DEBUG)
logger.setLevel(logging.DEBUG)


class TestWS(TestCase):
    valid_token = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz12"

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)
        self.ws = WS(url="app", user_key=self.valid_token,
                     token=self.valid_token, token_type=ORGANIZATION)

    def test_ws_constructor_invalid_user_key(self):
        with self.assertRaises(WsSdkTokenError):
            WS(user_key="INCORRECT", token=self.valid_token)

    # def test_ws_constructor_invalid_token(self):
    #     with self.assertRaises(WsSdkTokenError):
    #         WS(user_key="", token="INCORRECT")

    @patch('ws_sdk.web.requests.Session.post')
    def test__call_ws_api(self, mock_post):
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = '{"key": "val"}'
        res = self.ws.call_ws_api("api_call")

        self.assertIsInstance(res, dict)

    @patch('ws_sdk.web.json.loads')
    @patch('ws_sdk.web.requests.Session.post')
    def test__call_ws_api__bytes(self, mock_post, mock_json_loads):
        mock_post.return_value.status_code = 200
        mock_post.return_value.content = bytes()
        mock_post.return_value.encoding = None
        mock_json_loads.side_effect = json.JSONDecodeError(doc="DOC", pos=1, msg="Error")
        res = self.ws.call_ws_api("api_call")

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.json.loads')
    @patch('ws_sdk.web.requests.Session.post')
    def test__call_ws_api__text(self, mock_post, mock_json_loads):
        mock_post.return_value.status_code = 200
        mock_post.return_value.encoding = 'UTF-8'
        mock_post.return_value.text = "TEXT"
        mock_json_loads.side_effect = json.JSONDecodeError(doc="DOC", pos=1, msg="Error")
        res = self.ws.call_ws_api("api_call")

        self.assertIsInstance(res, str)

    @patch('ws_sdk.web.requests.Session.post')
    def test__call_ws_api_timeout_exception(self, mock_post):
        mock_post.side_effect = TimeoutError()

        with self.assertRaises(TimeoutError):
            self.ws.call_ws_api("api_call")

    @patch('ws_sdk.web.WS.call_ws_api')
    def test___generic_get__(self, mock_call_ws_api):
        mock_call_ws_api.return_value = []
        res = self.ws.__generic_get__(token_type=self.ws.token_type, get_type='suffix', kv_dict={})

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_organization_details')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_scopes(self, mock_generic_get, mock_get_organization_details):
        mock_generic_get.return_value = {'productVitals': [{'name': "PROD_NAME", 'token': "TOKEN"}]}
        mock_get_organization_details.return_value = {}
        res = self.ws.get_scopes(token="TOKEN")

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_name')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_scopes_as_product(self, mock_generic_get, mock_get_name):
        mock_generic_get.return_value = {'projectVitals': [{}]}
        mock_get_name.return_value = "PROD_NAME"
        self.ws.token_type = PRODUCT
        res = self.ws.get_scopes()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_report(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_alerts(report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_report_on_product(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_alerts(report=True, token="PROD_TOKEN")

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_by_type(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'alerts': {}}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        from_date = datetime.now()
        to_date = datetime.now()
        res = self.ws.get_alerts(alert_type='SECURITY_VULNERABILITY', from_date=from_date, to_date=to_date)

        self.assertIsInstance(res, dict)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_alerts_by_false_type(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_alerts(alert_type='FALSE')

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_all(self, mock_generic_get, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        mock_generic_get.return_value = {'alerts': []}
        res = self.ws.get_alerts()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_ignored(self, mock_generic_get, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        mock_generic_get.return_value = {'alerts': []}
        res = self.ws.get_alerts(ignored=True)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_ignored_report(self, mock_generic_get, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        mock_generic_get.return_value = {'alerts': []}
        res = self.ws.get_alerts(ignored=True, report=True)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_alerts')
    def test_get_ignored_alerts(self, mock_get_alerts):
        mock_get_alerts.return_value = []
        res = self.ws.get_ignored_alerts()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_resolved_report(self, mock_generic_get, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        mock_generic_get.return_value = bytes()
        res = self.ws.get_alerts(resolved=True, report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_alerts_just_resolved(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_alerts(resolved=True)

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.get_alerts')
    def test_get_resolved_alerts(self, mock_get_alerts):
        mock_get_alerts.return_value = bytes()
        res = self.ws.get_resolved_alerts(report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_alerts_by_project_tag(self, mock_generic_get, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        mock_generic_get.return_value = {'alerts': []}
        res = self.ws.get_alerts(tags={"key": "value"})

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_alerts_by_project_tag_product_token(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_alerts(tags={"key": "value"}, token=PRODUCT)

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_alerts_by_project_2_tags(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_alerts(tags={'k1': "v2", 'k2': "v2"})

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.get_scopes')
    def test_get_products(self, mock_get_scopes):
        mock_get_scopes.return_value = [{'type': PRODUCT}]
        res = self.ws.get_products()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_scopes')
    def test_get_projects(self, mock_get_scopes):
        mock_get_scopes.return_value = [{'type': PROJECT}]
        res = self.ws.get_projects()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_organization_details(self, mock_call_ws_api):
        mock_call_ws_api.return_value = {"orgName": "ORG_NAME", "orgToken": "ORG_TOKEN"}
        res = self.ws.get_organization_details()

        self.assertIsInstance(res, dict)

    @patch('ws_sdk.web.WS.get_organization_details')
    def test_get_name_as_org(self, mock_get_organization_details):
        mock_get_organization_details.return_value = {'orgName': "ORG_NAME"}
        res = self.ws.get_name()

        self.assertIsInstance(res, str)

    @patch('ws_sdk.web.WS.get_tags')
    def test_get_name_as_prod(self, mock_get_tags):
        self.ws.token_type = PRODUCT
        mock_get_tags.return_value = [{"name": "PROD_NAME"}]
        res = self.ws.get_name()

        self.assertIsInstance(res, str)

    def test_get_organization_details_not_org(self):
        self.ws.token_type = PRODUCT
        res = self.ws.get_organization_details()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_inventory_report(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_inventory(report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_inventory__product_report(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_inventory(token="PRODUCT", report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_inventory_project(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'libraries': []}
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_inventory(token="PROJECT", include_in_house_data=False)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_inventory(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'libraries': []}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_inventory()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_lib_dependencies(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = []
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_lib_dependencies(token="TOKEN", key_uuid="KEY_UUID")

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_scopes')
    def test_get_scopes_from_name(self, mock_get_scopes):
        mock_get_scopes.return_value = [{'name': "NAME", 'token': "TOKEN"}]
        res = self.ws.get_scopes_from_name(name="NAME")

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_scopes')
    def test_get_scopes_from_name_not_found(self, mock_get_scopes):
        mock_get_scopes.return_value = []
        res = self.ws.get_scopes_from_name("NAME")

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_scope_by_token')
    def test_get_scope_type_by_token(self, mock_get_scope_by_token):
        mock_get_scope_by_token.return_value = {'type': "TOKEN"}
        res = self.ws.get_scope_type_by_token(token="TOKEN")

        self.assertEqual(res, "TOKEN")

    @patch('ws_sdk.web.WS.get_scope_by_token')
    def test_get_scope_name_by_token(self, mock_get_scope_by_token):
        mock_get_scope_by_token.return_value = {'name': "NAME"}
        res = self.ws.get_scope_name_by_token(token="TOKEN")

        self.assertEqual(res, "NAME")

    @patch('ws_sdk.web.WS.get_scopes_from_name')
    def test_get_tokens_from_name(self, mock_get_scopes_from_name):
        mock_get_scopes_from_name.return_value = [{'name': "NAME", 'token': "TOKEN"}]
        res = self.ws.get_tokens_from_name('NAME')

        self.assertIsInstance(res, list) and self.assertDictEqual(res[0], {'name': "NAME", 'token': "TOKEN"})

    @patch('ws_sdk.web.WS.get_scopes')
    def test_get_scopes_by_token(self, mock_get_scopes):
        mock_get_scopes.return_value = [{'token': "TOKEN"}]
        res = self.ws.get_scope_by_token(token="TOKEN")

        self.assertIn('token', res) and self.assertEqual(res['token'], "TOKEN")

    @patch('ws_sdk.web.WS.get_scopes_from_name')
    def test_get_token_from_name_not_found(self, mock_get_scopes_from_name):
        mock_get_scopes_from_name.return_value = []
        res = self.ws.get_tokens_from_name('NAME_NOT_FOUND')

        self.assertIsInstance(res, list) and self.assertEqual(len(res), 0)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_vulnerability(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'vulnerabilities': []}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})

        res = self.ws.get_vulnerability()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_vulnerability_cluster(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'vulnerabilities': []}
        mock_set_token_in_body.return_value = (PRODUCT, {})

        res = self.ws.get_vulnerability(cluster=True, token=PRODUCT)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_vulnerability_cluster_as_org(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'vulnerabilities': []}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})

        res = self.ws.get_vulnerability(cluster=True)

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_vulnerability_report_xlsx_of_product(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_vulnerability(token="PRODUCT", report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.get_vulnerability')
    def test_get_vulnerabilities_per_lib(self, mock_get_vulnerability):
        mock_get_vulnerability.return_value = []
        res = self.ws.get_vulnerabilities_per_lib()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_change_log(self, mock_generic_get):
        mock_generic_get.return_value = {'changes': []}
        res = self.ws.get_change_log()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_change_log_start_date(self, mock_generic_get):
        mock_generic_get.return_value = {'changes': []}
        res = self.ws.get_change_log(start_date=datetime.now())

        self.assertIsInstance(res, list)

    @patch('ws_sdk.ws_constants.ENTITY_TYPES')
    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_assignments(self, mock_generic_get, mock_set_token_in_body, mock_entity_types):
        mock_generic_get.return_value = {}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        mock_entity_types.return_value = {}
        res = self.ws.get_user_group_assignments(entity_type=USERS,
                                                 role_type=RoleTypes.PRODUCT_INTEGRATOR)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_assignments_project(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {}
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_user_group_assignments()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_risk(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_risk()
        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_risk_project(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_risk()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_due_diligence(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_due_diligence()

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_attributes(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_attributes()

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_attributes__project(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_attributes()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_licenses(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'libraries': []}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_licenses(full_spdx=True)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_source_files(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'sourceFiles': []}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_source_files()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_source_files')
    def test_get_source_file_inventory(self, mock_get_source_files):
        mock_get_source_files.return_value = bytes()
        res = self.ws.get_source_file_inventory()

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_source_files_report(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_source_files(report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.get_in_house_libraries')
    def test_get_in_house(self, mock_get_in_house_libraries):
        mock_get_in_house_libraries.return_value = bytes()
        res = self.ws.get_in_house()

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_in_house_libraries(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'libraries': []}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_in_house_libraries()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_in_house_libraries_report(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_in_house_libraries(report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_library_location(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_library_location()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_library_location_on_project(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'libraryLocations': []}
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_library_location()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_license_compatibility_org_report(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_license_compatibility(report=True)

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_license_compatibility(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_license_compatibility()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_license_compatibility_report_prod(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_license_compatibility(report=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_license_compatibility_org(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_license_compatibility()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_licenses_histogram(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'licenseHistogram': {}}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_licenses(histogram=True)

        self.assertIsInstance(res, dict)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_attribution(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = dict()
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_attribution(reporting_aggregation_mode="BY_COMPONENT", token="TOKEN")

        self.assertIsInstance(res, dict)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_attribution_bin(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_attribution(reporting_aggregation_mode="BY_COMPONENT", token="TOKEN", report=True, export_format="TXT")

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_attribution_on_org(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})

        res = self.ws.get_attribution(reporting_aggregation_mode="BY_COMPONENT", token="TOKEN")
        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_effective_licenses(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_effective_licenses()

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_effective_licenses_project(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_effective_licenses()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_bugs(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_bugs()

        self.assertIsInstance(res, bytes)

    def test_get_bugs_not_report(self):
        res = self.ws.get_bugs(report=False)

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_request_history(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_request_history()

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_request_history_plugin(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_request_history(plugin=True)

        self.assertIsInstance(res, bytes)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_request_history_plugin_project(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = bytes()
        mock_set_token_in_body.return_value = (PROJECT, {})
        res = self.ws.get_request_history(plugin=True)

        self.assertIs(res, None)

    def test_get_request_history_not_report(self):
        res = self.ws.get_request_history(report=False)

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.get_projects')
    def test_get_project(self, mock_get_projects):
        mock_get_projects.return_value = [{'token': "TOKEN"}]
        res = self.ws.get_project(token="TOKEN")

        self.assertEqual(res['token'], "TOKEN")

    @patch('ws_sdk.web.WS.get_projects')
    def test_get_project_not_found(self, mock_get_projects):
        mock_get_projects.return_value = [{'token': "TOKEN"}]
        with self.assertRaises(WsSdkServerMissingTokenError):
            res = self.ws.get_project(token="NOT_FOUND")

    @patch('ws_sdk.web.WS.get_scopes')
    def test_get_product_of_project(self, mock_get_scopes):
        mock_get_scopes.return_value = [{'token': "TOKEN",
                                         'productToken': "PRODUCTTOKEN",
                                         'type': PROJECT}]

        res = self.ws.get_product_of_project(token="TOKEN")

        self.assertEqual(res['token'], "TOKEN")

    @patch('ws_sdk.web.WS.get_scope_name_by_token')
    @patch('ws_sdk.web.WS.call_ws_api')
    @patch('ws_sdk.web.WS.get_project')
    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_delete_scope(self, mock_set_token_in_body, mock_get_project, mock_call_ws_api,
                          mock_get_scope_name_by_token):
        mock_set_token_in_body.return_value = (PROJECT, {})
        mock_get_project.return_value = {'token': "TOKEN", 'productToken': "PROD_TOKEN"}
        mock_call_ws_api.return_value = {}
        mock_get_scope_name_by_token.return_value = "PROJECT_NAME"
        res = self.ws.delete_scope(token="TOKEN")

        self.assertIsInstance(res, dict)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_users(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'users': []}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_users()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_users_as_product(self, mock_set_token_in_body):
        self.ws.token_type = PRODUCT
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_users()

        self.assertIs(res, None)

    @patch('ws_sdk.web.WS.call_ws_api')
    def test_get_libraries(self, mock_call_ws_api):
        mock_call_ws_api.return_value = {'libraries': []}
        res = self.ws.get_libraries(search_value="LIB_NAME", version="VERSION", search_only_name=True)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.get_inventory')
    def test_get_libraries_not_global(self, mock_get_inventory):
        mock_get_inventory.return_value = []
        res = self.ws.get_libraries(search_value="LIB_NAME", global_search=False)

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_library_detailed(self, mock_generic_get):
        mock_generic_get.return_value = {"librariesInformation": []}
        res = self.ws.get_library_details(name="NAME", lib_type="Source Library", version="VERSION", languages=["java"])

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_tags_as_org(self, mock_generic_get, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        mock_generic_get.side_effect = [{'productTags': []}, {'projectTags': []}]
        res = self.ws.get_tags()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_tags_as_prod(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'projectTags': []}
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_tags()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.call_ws_api')
    def test_set_alerts_status(self, mock_call_ws_api, mock_set_token_in_body):
        mock_call_ws_api.return_value = {}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.set_alerts_status(alert_uuids="UUID", status=AlertStatus.AL_STATUS_IGNORED)

        self.assertIsInstance(res, dict)

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_set_alerts_status_no_uuids(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        with self.assertLogs(level='INFO') as cm:
            self.ws.set_alerts_status(alert_uuids=[], status=AlertStatus.AL_STATUS_ACTIVE)
            self.assertEqual(cm.output, ["ERROR:ws_sdk.web:At least 1 alert uuid must be provided"])

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_set_alerts_status_invalid_status(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        with self.assertLogs(level='INFO') as cm:
            self.ws.set_alerts_status(alert_uuids=["UUID"], status="INVALID")
            self.assertEqual(cm.output, ['ERROR:ws_sdk.web:INVALID status is invalid. Must be \"Ignored\" or \"Active\"'])

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_lib_notice(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = "TEXT"
        mock_set_token_in_body.return_value = (PRODUCT, {})
        res = self.ws.get_lib_notice(as_text=True)

        self.assertEqual(res, "TEXT")

    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_get_lib_notice_not_product(self, mock_set_token_in_body):
        mock_set_token_in_body.return_value = (self.ws.token_type, {})

        with self.assertRaises(WsSdkServerTokenTypeError):
            self.ws.get_lib_notice()

    @patch('ws_sdk.web.WS.call_ws_api')
    def test_set_lib_notice(self, mock_call_ws_api):
        mock_call_ws_api.return_value = []
        res = self.ws.set_lib_notice(lib_uuid='LIB_UUID', text=[{"k1": "v1", "k2": "v2"}, {"k1": "v1", "k2": "v2"}],
                                     reference='REFERENCE')

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_policies(self, mock_generic_get, mock_set_token_in_body):
        mock_generic_get.return_value = {'policies': [{'policyContext': 'DOMAIN'}]}
        mock_set_token_in_body.return_value = (self.ws.token_type, {})
        res = self.ws.get_policies()

        self.assertIsInstance(res, list)

    @patch('ws_sdk.web.WS.call_ws_api')
    @patch('ws_sdk.web.WS.get_users')
    def test_create_user(self, mock_get_users, mock_call_ws_api):
        mock_get_users.return_value = []
        mock_call_ws_api.return_value = {}

        with self.assertLogs(level='DEBUG') as cm:
            res = self.ws.create_user(name="NAME", email="EMAIL@ADDRESS.COM", inviter_email="INVITER@ADDRESS.COM")
            self.assertEqual(cm.output, ["DEBUG:ws_sdk.web:Token: 'None' is a organization",
                                         "DEBUG:ws_sdk.web:Creating User: NAME email : EMAIL@ADDRESS.COM with Inviter email: INVITER@ADDRESS.COM"])

    @patch('ws_sdk.web.WS.call_ws_api')
    @patch('ws_sdk.web.WS.get_users')
    def test_delete_user(self, mock_get_users, mock_call_ws_api):
        mock_get_users.return_value = [{"name": "USERNAME"}]
        mock_call_ws_api.return_value = {}

        with self.assertLogs(level='DEBUG') as cm:
            res = self.ws.delete_user(email="EMAIL@ADDRESS.COM")
            self.assertEqual(cm.output, [
                f"DEBUG:ws_sdk.web:Deleting user email: EMAIL@ADDRESS.COM from Organization Token: {self.ws.token}"])

    @patch('ws_sdk.web.WS.call_ws_api')
    @patch('ws_sdk.web.WS.get_groups')
    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_create_group(self, mock_set_token_in_body, mock_get_groups, mock_call_ws_api):
        mock_set_token_in_body.return_value = (PRODUCT, {})
        mock_get_groups.return_value = []
        mock_call_ws_api.return_value = {}

        with self.assertLogs(level='DEBUG') as cm:
            res = self.ws.create_group(name="GRP_NAME")
            self.assertEqual(cm.output, [f"DEBUG:ws_sdk.web:Creating Group: GRP_NAME"])

    @patch('ws_sdk.web.WS.set_token_in_body')
    @patch('ws_sdk.web.WS.get_users')
    @patch('ws_sdk.web.WS.get_groups')
    @patch('ws_sdk.web.WS.call_ws_api')
    def test_assign_user_to_group(self, mock_call_ws_api, mock_get_groups, mock_get_users, mock_set_token_in_body):
        mock_call_ws_api.return_value = []
        mock_get_groups.side_effect = [[{"name": "GRP_NAME"}], []]
        mock_get_users.return_value = [{"name": "USERNAME"}]
        mock_set_token_in_body.return_value = (self.ws.token_type, {})

        with self.assertLogs(level='DEBUG') as cm:
            res = self.ws.assign_user_to_group(user_email="EMAIL", group_name="GRP_NAME")
            self.assertEqual(cm.output, ["DEBUG:ws_sdk.web:Assigning user's Email: EMAIL to Group: GRP_NAME"])

    @patch('ws_sdk.web.WS.get_groups')
    @patch('ws_sdk.web.WS.__generic_set__')
    @patch('ws_sdk.web.WS.set_token_in_body')
    def test_assign_to_scope(self, mock_set_token_in_body, mock_generic_set, mock_get_groups):
        mock_generic_set.return_value = []
        mock_set_token_in_body.return_value = (PRODUCT, {})
        mock_get_groups.side_effect = [[{"name": "GRP_NAME"}], []]
        group_name = "GRP_NAME"

        with self.assertLogs(level='DEBUG') as cm:
            res = self.ws.assign_to_scope(role_type=RoleTypes.P_INTEGRATORS, group=group_name)
            self.assertEqual(cm.output, [
                f"DEBUG:ws_sdk.web:Assigning User(s): None Group(s): {group_name} to Role: {RoleTypes.P_INTEGRATORS}"])

    @patch('ws_sdk.web.WS.call_ws_api')
    def test_invite_user_to_web_advisor(self, mock_call_ws_api):
        with self.assertLogs(level='DEBUG') as cm:
            res = self.ws.invite_user_to_web_advisor(user_email="INVITEE@EMAIL.COM")
            self.assertEqual(cm.output, ["DEBUG:ws_sdk.web:Token: 'None' is a organization",
                                         "DEBUG:ws_sdk.web:Inviting email: 'INVITEE@EMAIL.COM' to Web Advisor"])

    @patch('ws_sdk.web.WS.call_ws_api')
    def test_regenerate_service_user_key(self, mock_call_ws_api):
        mock_call_ws_api.return_value = {'userToken': self.valid_token}
        res = self.ws.regenerate_service_user_key(service_user_key=self.valid_token)

        self.assertEqual(res, self.valid_token)

    @patch('ws_sdk.web.WS.__generic_get__')
    def test_get_integration_token(self, mock_generic_get):
        mock_generic_get.return_value = self.valid_token
        ret = self.ws.get_integration_token(integration_type=IntegrationTypes.INT_1)

        self.assertEqual(ret, self.valid_token)


if __name__ == '__main__':
    TestCase.unittest.main()

