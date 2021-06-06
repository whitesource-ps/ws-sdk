from typing import NamedTuple

# General
CACHE_TIME = 600
CONN_TIMEOUT = 3600
API_URL_SUFFIX = '/api/v1.3'
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
HEADERS = {'content-type': 'application/json'}
ALERT_STATUSES = ["Active", "Ignored"]


# Alert Types
class AlertTypes:
    REJECTED_BY_POLICY_RESOURCE = 'REJECTED_BY_POLICY_RESOURCE'
    MULTIPLE_LIBRARY_VERSIONS = 'MULTIPLE_LIBRARY_VERSIONS'
    NEW_MINOR_VERSION = 'NEW_MINOR_VERSION'
    NEW_MAJOR_VERSION = 'NEW_MAJOR_VERSION'
    SECURITY_VULNERABILITY = 'SECURITY_VULNERABILITY'

    ALERT_TYPES = [SECURITY_VULNERABILITY, NEW_MAJOR_VERSION, NEW_MINOR_VERSION, MULTIPLE_LIBRARY_VERSIONS,
                   REJECTED_BY_POLICY_RESOURCE]


# Scope Types
PROJECT = 'project'
PRODUCT = 'product'
ORGANIZATION = 'organization'

TOKEN_TYPES = {ORGANIZATION: "orgToken",
               PRODUCT: "productToken",
               PROJECT: "projectToken"
               }


# Role Types
class RoleTypes:
    DEFAULT_APPROVER = "DEFAULT_APPROVER"
    PRODUCT_INTEGRATOR = "PRODUCT_INTEGRATOR"
    ADMIN = "ADMIN"
    ROLE_TYPES = [DEFAULT_APPROVER, PRODUCT_INTEGRATOR, ADMIN]


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


class ReportsData:
    REPORT_BIN_TYPE = "report_bin_type"
    REPORT_META_DATA = [REPORT_BIN_TYPE]


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
