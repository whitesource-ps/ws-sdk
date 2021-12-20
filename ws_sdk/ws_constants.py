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
JAVA_BIN = "java"

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
    COLUMN_NAMES = "report_scope_column_names"
    REPORTS_META_DATA = [REPORT_BIN_TYPE, REPORT_SCOPE, COLUMN_NAMES]


class UAArchiveFiles:
    ARCHIVE_EXTRACTION_DEPTH_MAX = 10
    ALL_ARCHIVE_FILES = "**/*.aar", "**/*.car", "**/*.ear", "**/*.egg", "**/*.gem", "**/*.hpi", "**/*.jar", "**/*.nupkg", "**/*.rar", "**/*.rpm", "**/*.sca", "**/*.sda", "**/*.tar", "**/*.tar.bz2", "**/*.tar.gz", "**/*.tar.xz", "**/*.tgz", "**/*.war", "**/*.whl", "**/*.xz", "**/*.zip"


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

    class LangSuffix:
        C_SRC = ["**/*.c", "**/*.h"]
        CPP_SRC = ["**/*.cp", "**/*.cpp", "**/*.hpp", "**/*.c++", "**/*.cc", "**/*.hxx", "**/*.cxx", "**/*.h++"]
        C_SHRP_SRC = ["**/*.cs"]
        JAVA_BIN = ["**/*.jar", "**/*.war", "**/*.jar.pack.gz"]
        JAVA_SRC = ["**/*.java"]
        JAVA = JAVA_SRC + JAVA_BIN
        PYTHON_PKG = ["**/*.whl", "**/*.egg"]
        PYTHON_SRC = ["**/*.py", "**/*.py3"]
        PYTHON = PYTHON_SRC + PYTHON_PKG
        ARCHIVE = ["**/*.7z", "**/*.bz2", "**/*.tar", "**/*.tar.bz2", "**/*.tar.gz", "**/*.tbz", "**/*.tgz"]
        LINUX_PKG = ["**/*.rpm", "**/*.deb", "**/*.apk"]
        LINUX_LIB = ["**/*.so"]
        LINUX_MISC = ["**/*.awk", "**/*.nawk", "**/*.gawk", "**/*.zsh", "**/*.emacs"]
        WINDOWS_EXEC = ["**/*.exe", "**/*.bat"]
        WINDOWS_PKG = ["**/*.msi"]
        WINDOWS_LIB = ["**/*.dll"]
        ASP_SRC = ["**/*.asp", "**/*.aspx"]
        MAC_PKG = ["**/*.dmg"]
        APL_MISC_SRC = ["**/*.applescript"]
        RUBY_PKG = ["**/*.gem"]
        GO_SRC = ["**/*.go"]
        PERL_SRC = ["**/*.perl"]
        PHP_SRC = ["**/*.php", "**/*.php3", "**/*.php4", "**/*.php5"]
        PASCAL = ["**/*.pascal"]
        JAVASCRIPT_SRC = ["**/*.js", "**/*.min.js", "**/*.jsx"]
        LISP = ["**/*.lisp"]
        ASSORTED_SUFFICES = ["**/*.a", "**/*.aar", "**/*.air", "**/*.ar", "**/*.car","**/*.conda", "**/*.cpa", "**/*.crate", "**/*.docker",
                            "**/*.drpm", "**/*.ear", "**/*.epk", "**/*.gal", "**/*.gzip", "**/*.har", "**/*.hpi", "**/*.jpi",
                            "**/*.ko", "**/*.nupkg", "**/*.pkg.tar.xz", "**/*.sar", "**/*.sit", "**/*.swc", "**/*.swf", "**/*.udeb", "**/*.zip",
                            "**/*.4th", "**/*.6pl", "**/*.6pm", "**/*.8xk", "**/*.8xk.txt", "**/*.8xp", "**/*.8xp.txt", "**/*.E", "**/*.ML", "**/*._coffee", "**/*._js", "**/*._ls", "**/*.abap", "**/*.ada",
                            "**/*.adb", "**/*.ado", "**/*.adp", "**/*.ads", "**/*.agda", "**/*.ahk", "**/*.ahkl", "**/*.aidl", "**/*.aj", "**/*.al", "**/*.als", "**/*.ampl", "**/*.apl", "**/*.app.src",
                              "**/*.arc", "**/*.as", "**/*.asax", "**/*.asc", "**/*.ascx", "**/*.asd", "**/*.ash", "**/*.ashx", "**/*.asmx", "**/*.au3", "**/*.aug",
                             "**/*.auk", "**/*.aw", "**/*.axd", "**/*.axi", "**/*.axi.erb", "**/*.axs", "**/*.axs.erb", "**/*.b", "**/*.bas", "**/*.bash", "**/*.bats", "**/*.bb",
                             "**/*.befunge", "**/*.bf", "**/*.bison", "**/*.bmx", "**/*.bones", "**/*.boo", "**/*.boot",
                             "**/*.brd", "**/*.bro", "**/*.brs", "**/*.bsl", "**/*.bsv", "**/*.builder", "**/*.bzl",
                             "**/*.cake", "**/*.capnp", "**/*.cats", "**/*.cbl",
                             "**/*.ccp", "**/*.cdf", "**/*.ceylon", "**/*.cfc", "**/*.cfm", "**/*.cfml", "**/*.cgi",
                             "**/*.ch", "**/*.chpl", "**/*.chs", "**/*.cirru", "**/*.cjsx", "**/*.ck", "**/*.cl",
                             "**/*.cl2", "**/*.click", "**/*.clj", "**/*.cljc", "**/*.cljs", "**/*.cljs.hl",
                             "**/*.cljscm", "**/*.cljx", "**/*.clp", "**/*.cls", "**/*.clw", "**/*.cmd", "**/*.cob",
                             "**/*.cobol", "**/*.coffee", "**/*.com", "**/*.command", "**/*.coq",
                             "**/*.cps", "**/*.cpy", "**/*.cr", "**/*.csd", "**/*.cshtml", "**/*.csx",
                             "**/*.ctp", "**/*.cu", "**/*.cuh", "**/*.cw", "**/*.cy", "**/*.d", "**/*.dart",
                             "**/*.dats", "**/*.db2", "**/*.dcl", "**/*.decls", "**/*.dfm", "**/*.di", "**/*.djs",
                             "**/*.dlm", "**/*.dm", "**/*.do", "**/*.doh", "**/*.dpr", "**/*.druby", "**/*.duby",
                             "**/*.dyalog", "**/*.dyl", "**/*.dylan", "**/*.e", "**/*.ec", "**/*.ecl", "**/*.eclxml",
                             "**/*.eh", "**/*.el", "**/*.eliom", "**/*.eliomi", "**/*.elm", "**/*.em",
                             "**/*.emacs.desktop", "**/*.emberscript", "**/*.eq", "**/*.erl", "**/*.es", "**/*.es6",
                             "**/*.escript", "**/*.ex", "**/*.exs", "**/*.eye", "**/*.f", "**/*.f03", "**/*.f08",
                             "**/*.f77", "**/*.f90", "**/*.f95", "**/*.factor", "**/*.fan", "**/*.fancypack", "**/*.fcgi",
                             "**/*.feature", "**/*.flex", "**/*.flux", "**/*.for", "**/*.forth", "**/*.fp", "**/*.fpp",
                             "**/*.fr", "**/*.frag", "**/*.frg", "**/*.frm", "**/*.frt", "**/*.frx", "**/*.fs", "**/*.fsh",
                             "**/*.fshader", "**/*.fsi", "**/*.fsx", "**/*.fth", "**/*.ftl", "**/*.fun", "**/*.fx",
                             "**/*.fxh", "**/*.fy", "**/*.g", "**/*.g4", "**/*.gap", "**/*.gd", "**/*.gdb",
                             "**/*.gdbinit", "**/*.gemspec", "**/*.geo", "**/*.geom", "**/*.gf", "**/*.gi", "**/*.glf",
                             "**/*.glsl", "**/*.glslv", "**/*.gml", "**/*.gms", "**/*.gnu", "**/*.gnuplot",
                             "**/*.god", "**/*.golo", "**/*.gp", "**/*.grace", "**/*.groovy", "**/*.grt", "**/*.gs",
                             "**/*.gshader", "**/*.gsp", "**/*.gst", "**/*.gsx", "**/*.gtpl", "**/*.gvy", "**/*.gyp",
                             "**/*.gypi", "**/*.hats", "**/*.hb", "**/*.hcl", "**/*.hh", "**/*.hic",
                             "**/*.hlean", "**/*.hlsl", "**/*.hlsli", "**/*.hqf", "**/*.hrl", "**/*.hs",
                             "**/*.hsc", "**/*.hx", "**/*.hxsl", "**/*.hy", "**/*.i7x", "**/*.iced",
                             "**/*.icl", "**/*.idc", "**/*.idr", "**/*.ihlp", "**/*.ijs", "**/*.ik", "**/*.ily",
                             "**/*.inc", "**/*.inl", "**/*.ino", "**/*.intr", "**/*.io", "**/*.ipf", "**/*.ipp",
                             "**/*.irbrc", "**/*.iss", "**/*.j", "**/*.jake", "**/*.jbuilder", "**/*.jflex",
                             "**/*.ji", "**/*.jison", "**/*.jisonlex", "**/*.jl", "**/*.jq", "**/*.jsb",
                             "**/*.jscad", "**/*.jsfl", "**/*.jsm", "**/*.jsp", "**/*.jss", "**/*.kicad_pcb",
                             "**/*.kid", "**/*.krl", "**/*.ksh", "**/*.kt", "**/*.ktm", "**/*.kts", "**/*.l", "**/*.lagda",
                             "**/*.las", "**/*.lasso", "**/*.lasso8", "**/*.lasso9", "**/*.ldml", "**/*.lean", "**/*.lex",
                             "**/*.lfe", "**/*.lgt", "**/*.lhs", "**/*.lid", "**/*.lidr", "**/*.litcoffee",
                             "**/*.ll", "**/*.lmi", "**/*.logtalk", "**/*.lol", "**/*.lookml", "**/*.lpr", "**/*.ls",
                             "**/*.lsl", "**/*.lslp", "**/*.lsp", "**/*.lua", "**/*.lvproj", "**/*.ly", "**/*.m",
                             "**/*.m4", "**/*.ma", "**/*.mak", "**/*.make", "**/*.mako", "**/*.mao", "**/*.mata",
                             "**/*.matah", "**/*.mathematica", "**/*.matlab", "**/*.mawk", "**/*.maxhelp", "**/*.maxpat",
                             "**/*.maxproj", "**/*.mcr", "**/*.metal", "**/*.minid", "**/*.mir", "**/*.mirah", "**/*.mk",
                             "**/*.mkfile", "**/*.ml", "**/*.ml4", "**/*.mli", "**/*.mll", "**/*.mly", "**/*.mm",
                             "**/*.mmk", "**/*.mms", "**/*.mo", "**/*.mod", "**/*.model.lkml", "**/*.monkey", "**/*.moo",
                             "**/*.moon", "**/*.mq4", "**/*.mq5", "**/*.mqh", "**/*.ms", "**/*.mspec", "**/*.mss",
                             "**/*.mt", "**/*.mu", "**/*.muf", "**/*.mumps", "**/*.mxt", "**/*.myt", "**/*.n",
                             "**/*.nb", "**/*.nbp", "**/*.nc", "**/*.ncl", "**/*.ni", "**/*.nim", "**/*.nimrod",
                             "**/*.nit", "**/*.nix", "**/*.njs", "**/*.nl", "**/*.nlogo", "**/*.nqp", "**/*.nse",
                             "**/*.nsh", "**/*.nsi", "**/*.nu", "**/*.numpy", "**/*.numpyw", "**/*.numsc", "**/*.nut",
                             "**/*.ny", "**/*.omgrofl", "**/*.ooc", "**/*.opa", "**/*.opal", "**/*.opencl", "**/*.orc",
                             "**/*.os", "**/*.ox", "**/*.oxh", "**/*.oxo", "**/*.oxygene", "**/*.oz", "**/*.p", "**/*.p4",
                             "**/*.p6", "**/*.p6l", "**/*.p6m", "**/*.pac", "**/*.pan", "**/*.parrot", "**/*.pas",
                             "**/*.pasm", "**/*.pat", "**/*.pb", "**/*.pbi", "**/*.pbt", "**/*.pck",
                             "**/*.pd", "**/*.pd_lua", "**/*.pde", "**/*.ph", "**/*.phps", "**/*.phpt", "**/*.pig", "**/*.pike", "**/*.pir",
                             "**/*.pkb", "**/*.pks", "**/*.pl", "**/*.pl6", "**/*.plb", "**/*.plot", "**/*.pls",
                             "**/*.plsql", "**/*.plt", "**/*.pluginspec", "**/*.plx", "**/*.pm", "**/*.pm6", "**/*.pmod",
                             "**/*.pod", "**/*.podsl", "**/*.podspec", "**/*.pogo", "**/*.pony", "**/*.pov", "**/*.pp",
                             "**/*.pprx", "**/*.prg", "**/*.pri", "**/*.pro", "**/*.prolog", "**/*.prw", "**/*.ps1",
                             "**/*.psc", "**/*.psd1", "**/*.psgi", "**/*.psm1", "**/*.purs", "**/*.pwn", "**/*.pxd",
                             "**/*.pxi", "**/*.pyde", "**/*.pyp", "**/*.pyt", "**/*.pyw",
                             "**/*.pyx", "**/*.qbs", "**/*.qml", "**/*.r", "**/*.r2", "**/*.r3", "**/*.rabl", "**/*.rake",
                             "**/*.rb", "**/*.rbbas", "**/*.rbfrm", "**/*.rbmnu", "**/*.rbres", "**/*.rbtbar",
                             "**/*.rbuild", "**/*.rbuistate", "**/*.rbw", "**/*.rbx", "**/*.rbxs", "**/*.rd", "**/*.re",
                             "**/*.reb", "**/*.rebol", "**/*.red", "**/*.reds", "**/*.rei", "**/*.rex", "**/*.rexx",
                             "**/*.rg", "**/*.rkt", "**/*.rktd", "**/*.rktl", "**/*.rl", "**/*.rpy", "**/*.rs",
                             "**/*.rs.in", "**/*.rsc", "**/*.rsh", "**/*.rsx", "**/*.ru", "**/*.ruby", "**/*.sage",
                             "**/*.sagews", "**/*.sas", "**/*.sats", "**/*.sbt", "**/*.sc", "**/*.scad", "**/*.scala",
                             "**/*.scd", "**/*.sce", "**/*.sch", "**/*.sci", "**/*.scm", "**/*.sco", "**/*.scpt",
                             "**/*.scrbl", "**/*.self", "**/*.sexp", "**/*.sh", "**/*.sh-session", "**/*.sh.in",
                             "**/*.shader", "**/*.shen", "**/*.sig", "**/*.sj", "**/*.sjs", "**/*.sl", "**/*.sld",
                             "**/*.sls", "**/*.sma", "**/*.smali", "**/*.sml", "**/*.smt", "**/*.smt2", "**/*.sp",
                             "**/*.spec", "**/*.spin", "**/*.sps", "**/*.sqf", "**/*.sql", "**/*.sra", "**/*.sru",
                             "**/*.srw", "**/*.ss", "**/*.ssjs", "**/*.st", "**/*.stan", "**/*.sthlp", "**/*.sv",
                             "**/*.svh", "**/*.swift", "**/*.t", "**/*.tac", "**/*.tcc", "**/*.tcl", "**/*.tf",
                             "**/*.thor", "**/*.thrift", "**/*.thy", "**/*.tla", "**/*.tm", "**/*.tmux", "**/*.tool",
                             "**/*.tpl", "**/*.tpp", "**/*.ts", "**/*.tst", "**/*.tsx", "**/*.tu", "**/*.txl", "**/*.uc",
                             "**/*.udo", "**/*.uno", "**/*.upc", "**/*.ur", "**/*.urs", "**/*.v", "**/*.vala", "**/*.vapi",
                             "**/*.vark", "**/*.vb", "**/*.vba", "**/*.vbhtml", "**/*.vbs", "**/*.vcl", "**/*.veo",
                             "**/*.vert", "**/*.vh", "**/*.vhd", "**/*.vhdl", "**/*.vhf", "**/*.vhi", "**/*.vho",
                             "**/*.vhs", "**/*.vht", "**/*.vhw", "**/*.view.lkml", "**/*.vim", "**/*.volt", "**/*.vrx",
                             "**/*.vsh", "**/*.vshader", "**/*.w", "**/*.watchr", "**/*.webidl", "**/*.wisp", "**/*.wl",
                             "**/*.wlt", "**/*.wlua", "**/*.wsgi", "**/*.x", "**/*.x10", "**/*.xc", "**/*.xi", "**/*.xm",
                             "**/*.xojo_code", "**/*.xojo_menu", "**/*.xojo_report", "**/*.xojo_script", "**/*.xojo_toolbar",
                             "**/*.xojo_window", "**/*.xpl", "**/*.xproc", "**/*.xpy", "**/*.xq", "**/*.xql", "**/*.xqm",
                             "**/*.xquery", "**/*.xqy", "**/*.xrl", "**/*.xs", "**/*.xsjs", "**/*.xsjslib", "**/*.xsl",
                             "**/*.xslt", "**/*.xsp-config", "**/*.xsp.metadata", "**/*.xtend", "**/*.y", "**/*.yacc",
                             "**/*.yap", "**/*.yrl", "**/*.yy", "**/*.zep", "**/*.zimpl", "**/*.zmpl", "**/*.zpl"]
        # ALL_SUFFICES =
        UA_DEFAULT = C_SRC + CPP_SRC


class ScopeSorts:
    NAME = "name"
    UPDATE_TIME = "lastUpdatedDate_obj"
    CREATE_TIME = "creationDate_obj"

    SCOPE_SORTS = [NAME, UPDATE_TIME, CREATE_TIME]


class IntegrationTypes:
    INT_1 = "int__1"
    Types = [INT_1]
