import logging
import os
import sys
import getpass
import argparse
from ws_sdk.web import WS
from spdx.document import Document, License
from spdx.writers import json as spdx_json
from spdx import file, package, version, config, creationinfo
from spdx.utils import NoAssert, SPDXNone
from spdx.checksum import Algorithm
from datetime import datetime

logging.basicConfig(level=logging.DEBUG,
                    stream=sys.stdout,
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

ws_conn = report_token = None


def init(token):
    global ws_conn
    ws_conn = WS(url=os.environ['WS_URL'], user_key=os.environ['WS_USER_KEY'], token=os.environ['WS_ORG_TOKEN'])


def create_sbom_doc(token: str):
    init(token)
    doc = create_document(token)
    doc.package = create_package(token)
    doc.package.files, licenses_from_files = create_files(token)

    # After file section creation
    doc.package.verif_code = doc.package.calc_verif_code()
    doc.package.licenses_from_files = licenses_from_files

    with open("spdx_out.json", "w") as fp:
        spdx_json.write_document(doc, fp)


def create_document(token: str) -> Document:
    global ws_conn
    scope_name = ws_conn.get_scope_name_by_token(token)
    document = Document(name=f"WhiteSource {scope_name} SBOM report",
                        namespace=f"http://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]",    # UNKNOWN FROM WS
                        spdx_id="SPDXRef-DOCUMENT",
                        version=version.Version(2, 2),
                        data_license=License.from_identifier("CC0-1.0"))
    # Creation Info
    document.creation_info.set_created_now()
    org = creationinfo.Organization(ws_conn.get_organization_name(), "OPT_EMAIL")   # UNKNOWN FROM WS
    tool = creationinfo.Tool("White Source SBOM Report Generator")
    person = creationinfo.Person(getpass.getuser(), "OPT_EMAIL")                           # UNKNOWN FROM WS MAYBE FROM OS
    document.creation_info.add_creator(org)
    document.creation_info.add_creator(tool)
    document.creation_info.add_creator(person)

    return document


def create_package(token: str) -> package.Package:
    global ws_conn
    pkg = package.Package(name=ws_conn.get_scope_name_by_token(token),
                              spdx_id="SPDXRef-1",
                              download_location=SPDXNone())                         # UNKNOWN FROM WS
    pkg.check_sum = Algorithm(identifier="SHA1", value="")                          # UNKNOWN FROM WS
    pkg.cr_text = NoAssert()                                                        # UNKNOWN FROM WS
    pkg.conc_lics = NoAssert()                                                      # UNKNOWN FROM WS
    pkg.license_declared = NoAssert()                                               # UNKNOWN FROM WS

    return pkg


def create_files(token: str):
    files = []
    all_licenses_from_files = set()        # TODO FILL THIS IN
    spdx_file = file.File(name="FILE_NAME",
                          spdx_id="FILE_ID",
                          chk_sum=Algorithm(identifier="SHA1", value="FILE_HASH?"))
    spdx_file.conc_lics = SPDXNone()
    spdx_file.licenses_in_file.append("LICENSE_1")
    spdx_file.copyright = SPDXNone()

    files.append(spdx_file)

    return files, all_licenses_from_files




def assign_spdx_lic_to_report(token: str):
    libs = ws_conn.get_licenses(token=token)
    for lib in libs:
        logging.debug(f"Working on library: {lib['name']}")
        for lic in lib['licenses']:
            # lookup_val = fix_license_id(lic['spdxName'])
            logging.debug(f"Searching for: {lic['spdxName']}")
            # logging.debug(f"Searching for: {lookup_val} (Original value: {lic['spdxName']})")
            try:
                lic['spdx_license_list'] = config.load_license_list()[lic['spdxName']]  # load_license_list probly return tuple from licenses.json
            except KeyError:
                logging.error(f"Could not find SPDX result for value: {lic['spdxName']}")

    return libs


if __name__ == '__main__':
    create_sbom_doc(sys.argv[1])
    # inventory = ws_conn.get_inventory(token=sys.argv[1])
    # dd = ws_conn.get_due_diligence(token=sys.argv[1])
    logging.info("Done")
