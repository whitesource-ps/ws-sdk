import sys
from typing import NamedTuple

# General
CACHE_TIME = 300
CONN_TIMEOUT = 3600
API_URL_SUFFIX = '/api/v1.3'
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
WS_HEADERS = {'content-type': 'application/json'}
DEFAULT_REMOTE_URL = ""
INVALID_FS_CHARS = [':', '*', '\\', '<', '>', '/', '"', '?', '|']


# UA
DEFAULT_UA_PATH = "c:\\tmp\\ua" if sys.platform.startswith("win") else "/tmp/ua"
UA_JAR_F_N = "wss-unified-agent.jar"
UA_CONF_F_N = "wss-unified-agent.config"
LATEST_UA_CONF_F_U = "https://github.com/whitesource/unified-agent-distribution/raw/master/standAlone/wss-unified-agent.config"
LATEST_UA_JAR_F_U = "https://github.com/whitesource/unified-agent-distribution/releases/latest/download/wss-unified-agent.jar"

UA_JAR_T = (UA_JAR_F_N, LATEST_UA_JAR_F_U)
UA_CONF_T = (UA_CONF_F_N, LATEST_UA_CONF_F_U)

LATEST_UA_URL = "https://api.github.com/repos/whitesource/unified-agent-distribution/releases/latest"
GH_HEADERS = {"Accept": "application / vnd.github.v3 + json"}
MANDATORY_VALS = ['TBD']


class AlertStatus:
    AL_STATUS_IGNORED = "Ignored"
    AL_STATUS_ACTIVE = "Active"
    AL_STATUS_RESOLVED = "Active"
    ALERT_STATUSES = [AL_STATUS_ACTIVE, AL_STATUS_IGNORED, AL_STATUS_RESOLVED]
    ALERT_SET_STATUSES = [AL_STATUS_ACTIVE, AL_STATUS_IGNORED]


# Alert Types
class AlertTypes:
    REJECTED_BY_POLICY_RESOURCE = 'REJECTED_BY_POLICY_RESOURCE'
    MULTIPLE_LIBRARY_VERSIONS = 'MULTIPLE_LIBRARY_VERSIONS'
    NEW_MINOR_VERSION = 'NEW_MINOR_VERSION'
    NEW_MAJOR_VERSION = 'NEW_MAJOR_VERSION'
    SECURITY_VULNERABILITY = 'SECURITY_VULNERABILITY'

    ALERT_TYPES = [SECURITY_VULNERABILITY, NEW_MAJOR_VERSION, NEW_MINOR_VERSION, MULTIPLE_LIBRARY_VERSIONS,
                   REJECTED_BY_POLICY_RESOURCE]


# Scope Types - Deprecated
PROJECT = 'project'
PRODUCT = 'product'
ORGANIZATION = 'organization'
GLOBAL = 'globalOrganization'


class ScopeTypes:
    PROJECT = 'project'
    PRODUCT = 'product'
    ORGANIZATION = 'organization'
    GLOBAL = 'globalOrganization'
    SCOPE_TYPES = [PROJECT, PRODUCT, ORGANIZATION, GLOBAL]


TOKEN_TYPES_MAPPING = {ScopeTypes.GLOBAL: "globalOrgToken",
                       ScopeTypes.ORGANIZATION: "orgToken",
                       ScopeTypes.PRODUCT: "productToken",
                       ScopeTypes.PROJECT: "projectToken"}


# Role Types
class RoleTypes:
    DEFAULT_APPROVER = "DEFAULT_APPROVER"
    PRODUCT_INTEGRATOR = "PRODUCT_INTEGRATOR"
    ADMIN = "ADMIN"

    ROLE_TYPES = [DEFAULT_APPROVER, PRODUCT_INTEGRATOR, ADMIN]

    O_ADMINISTRATORS = "administrators"
    O_ALERT_RECEIVERS = "alertsEmailReceivers"
    O_DEFAULT_APPROVERS = "defaultApprover"
    O_READ_ONLY_USERS = "readOnlyUsers"
    P_ADMIN = "productAdmins"
    P_ALERT_RECEIVERS = "alertsEmailReceivers"
    P_ASSIGNMENTS = "productMembership"
    P_DEFAULT_APPROVERS = "productApprovers"
    P_INTEGRATORS = "productIntegrators"

    ORG_ROLE_TYPES = [O_ADMINISTRATORS, O_ALERT_RECEIVERS, O_DEFAULT_APPROVERS, O_READ_ONLY_USERS]
    PROD_ROLES_TYPES = [P_ADMIN, P_ALERT_RECEIVERS, P_ASSIGNMENTS, P_DEFAULT_APPROVERS, P_INTEGRATORS, P_ASSIGNMENTS]
    ALL_ROLE_TYPES = ORG_ROLE_TYPES + PROD_ROLES_TYPES


# Assignments
GROUPS = "groups"
USERS = "users"
ENTITY_TYPES = {GROUPS: "groupRoles",
                USERS: "userRoles"}


# Library Types for search
class LibTypes:
    LIB_T_JAVA = "maven"
    LIB_T_PYTHON = "pypi"
    LIB_T_GO = "go"
    LIB_T_DOCKER ="docker"
    LIB_T_DOTNET =".net"
    LIB_T_ACTIONSCRIPT = "actionscript"
    LIB_T_ALPINE = "alpine"
    LIB_T_DEBIAN = "debian"
    LIB_T_DOCKER_LAYER = "docker_layer"
    LIB_T_ERLANG = "hex"
    LIB_T_HASKELL = "haskell"
    LIB_T_JS_BOWER = "bower"
    LIB_T_JS_NPM = "npm"
    LIB_T_OCAML = "ocaml"
    LIB_T_PHP = "php"
    LIB_T_R = "R"
    LIB_T_RPM = "RPM"
    LIB_T_RUBY = "Ruby"
    LIB_T_RUST = "Rust"
    LIB_T_OBJC = "cocoaPods"
    LIB_T_NUGET = "Nuget"       # YES?

    #                 # Language, Package Manager, Common Suffixes
    # L_TYPES = set(('java', ['maven', 'gradle', 'ant'], ['jar']),
    #               ('javascript', ['npm', 'bower', 'nuget'], ['js']),
    #               ('python', ['pip'], ['py']),
    #               )

    LIB_TYPES = [LIB_T_NUGET, LIB_T_OBJC, LIB_T_R, LIB_T_GO, LIB_T_RUST, LIB_T_RUBY, LIB_T_RPM, LIB_T_ACTIONSCRIPT,
                 LIB_T_ALPINE, LIB_T_DEBIAN, LIB_T_DOCKER, LIB_T_DOTNET, LIB_T_DOCKER_LAYER, LIB_T_ERLANG, LIB_T_JAVA,
                 LIB_T_HASKELL, LIB_T_PYTHON, LIB_T_JS_BOWER , LIB_T_JS_NPM, LIB_T_OCAML, LIB_T_PHP]

    type_to_lib_t = {"Java": LIB_T_JAVA,
                    "Python": LIB_T_PYTHON,
                    "Source Library": LIB_T_GO,
                    "UNKNOWN": LIB_T_DOCKER,
                    ".NET": LIB_T_DOTNET,
                    "UNKNOWN": LIB_T_ACTIONSCRIPT,
                    "Alpine": LIB_T_ALPINE,
                    "Debian": LIB_T_DEBIAN,
                    "UNKNOWN": LIB_T_DOCKER_LAYER,
                    "Source Library": LIB_T_ERLANG,
                    "UNKNOWN": LIB_T_HASKELL,
                    "UNKNOWN": LIB_T_JS_BOWER,
                    "javascript/Node.js": LIB_T_JS_NPM,
                    "UNKNOWN": LIB_T_OCAML,
                    "Source Library": LIB_T_PHP,
                    "R": LIB_T_R,
                    "RPM": LIB_T_RPM,
                    "Ruby": LIB_T_RUBY,
                    "Source Library": LIB_T_RUST,
                    "CocoaPods": LIB_T_OBJC,
                    "Nuget": LIB_T_NUGET}  # YES?


class ReportsMetaData(NamedTuple):
    name: str
    bin_sfx: str
    func: callable

    REPORT_BIN_TYPE = "report_bin_type"
    REPORT_SCOPE = "report_scope_types"
    REPORTS_META_DATA = [REPORT_BIN_TYPE, REPORT_SCOPE]


class LibMetaData:
    class LibMetadata(NamedTuple):
        language: str
        package_manager: list
        file_suffices: list

    L_TYPES = [LibMetadata(language='java', package_manager=['maven', 'gradle', 'ant'], file_suffices=['jar']),
               LibMetadata(language='python', package_manager=['pip'], file_suffices=['py']),
               LibMetadata(language='javascript', package_manager=['npm', 'bower', 'nuget'], file_suffices=['js']),
               LibMetadata(language='ruby', package_manager=['rubygems'], file_suffices=['rb']),
               LibMetadata(language='.net', package_manager=['nuget'], file_suffices=['cs']),
               LibMetadata(language='rust', package_manager=['cargo'], file_suffices=['rs', 'rlib']),
               LibMetadata(language='go', package_manager=[], file_suffices=['go']),
               LibMetadata(language='r', package_manager=[], file_suffices=['r']),
               LibMetadata(language='objc', package_manager=['cocoapods'], file_suffices=['.h', '.m', '.mm', '.M']),
               ]


class ScopeSorts:
    NAME = "name"
    UPDATE_TIME = "lastUpdatedDate_obj"
    CREATE_TIME = "creationDate_obj"

    SCOPE_SORTS = [NAME, UPDATE_TIME, CREATE_TIME]


class IntegrationTypes:
    INT_1 = "int__1"
    Types = [INT_1]
