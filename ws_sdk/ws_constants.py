# General
CACHE_TIME = 600
API_URL_SUFFIX = '/api/v1.3'
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
HEADERS = {'content-type': 'application/json'}
# Alert Typs
REJECTED_BY_POLICY_RESOURCE = 'REJECTED_BY_POLICY_RESOURCE'
MULTIPLE_LIBRARY_VERSIONS = 'MULTIPLE_LIBRARY_VERSIONS'
NEW_MINOR_VERSION = 'NEW_MINOR_VERSION'
NEW_MAJOR_VERSION = 'NEW_MAJOR_VERSION'
SECURITY_VULNERABILITY = 'SECURITY_VULNERABILITY'
# Scope Types
PROJECT = 'project'
PRODUCT = 'product'
ORGANIZATION = 'organization'
ALERT_TYPES = [SECURITY_VULNERABILITY, NEW_MAJOR_VERSION, NEW_MINOR_VERSION, MULTIPLE_LIBRARY_VERSIONS, REJECTED_BY_POLICY_RESOURCE]
TOKEN_TYPES = {ORGANIZATION: "orgToken",
               PRODUCT: "productToken",
               PROJECT: "projectToken"
               }
# Role Types
DEFAULT_APPROVER = "DEFAULT_APPROVER"
PRODUCT_INTEGRATOR = "PRODUCT_INTEGRATOR"
ADMIN = "ADMIN"
ROLE_TYPES = [DEFAULT_APPROVER, PRODUCT_INTEGRATOR, ADMIN]
# Assignments
GROUPS = "groups"
USERS = "users"
ENTITY_TYPES = {GROUPS: "groupRoles",
                USERS: "userRoles"}
LIBRARY_TYPES = ["go", "maven", "pypi", "docker" ".net", "actionscript", "alpine", "debian", "docker_layer", "hex",
                 "haskell", "bower", "npm", "ocaml", "php", "R", "RPM", "Ruby", "Rust", "cocoaPods"]
