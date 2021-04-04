import logging
import os
import sys
import getpass
import argparse
from ws_sdk.web import WS
import spdx_license_list
from spdx.document import Document, License
from spdx.writers import json as spdx_json
from spdx import file, package, version
from spdx.utils import NoAssert, SPDXNone
from spdx.checksum import Algorithm

# from spdx.creationinfo import Tool
# from spdx.document import License
# from spdx.document import ExtractedLicense, ExternalDocumentRef

from datetime import datetime

logging.basicConfig(level=logging.DEBUG,
                    stream=sys.stdout,
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

ws_url = ws_org_token = ws_user_key =  ws_conn = document_header = None


def init(token):
    global ws_url, ws_org_token, ws_user_key, ws_conn, document_header
    ws_url = os.environ['WS_URL']
    ws_org_token = os.environ['WS_ORG_TOKEN']
    ws_user_key = os.environ['WS_USER_KEY']

    ws_conn = WS(url=ws_url, user_key=ws_user_key, token=ws_org_token)
    document_header = {"SPDXVersion": "SPDX-2.2",
                       "DataLicense": "CC0-1.0",
                       "SPDXID": "SPDXRef-DOCUMENT",
                       "DocumentName": f"{ws_conn.get_scope_name_by_token(token)} SBOM",
                       "DocumentNamespace": "https://swinslow.net/spdx-examples/example6/hello-go-bin-v1",
                       "ExternalDocumentRef":"DocumentRef-hello-go-src https://swinslow.net/spdx-examples/example6/hello-go-src-v1",
                       "SHA256": "5aac40a3b28b4a0a571a327631d752ffda7d4631093b035f38bd201baa45565e",
                       "ExternalDocumentRef": "DocumentRef-go-lib https://swinslow.net/spdx-examples/example6/go-lib-v1",
                       "SHA256": "d2048fd27e4aec3c0ebe5e899620ea4cd94a2aac2682740e06386eb50533fe41",
                       "Creator": f"Person: {getpass.getuser()}",
                       "Creator": "Tool: WhiteSource SBOM tool",
                       "Created": datetime.now()
                       }


def create_files(document: Document):
    spdx_file = file.File(name="FILE_NAME",
                          spdx_id="FILE_ID",
                          chk_sum=Algorithm(identifier="SHA1", value="FILE_HASH?"))
    spdx_file.conc_lics = SPDXNone()
    spdx_file.licenses_in_file.append("LICENSE_1")
    spdx_file.copyright = SPDXNone()

    document.package.add_file(spdx_file)


def create_package(doc):
    doc.package = package.Package(name="PKG_NAME",
                                  spdx_id="PKG_ID",
                                  download_location="DL_LOCATION",
                                  version="PKG_VERSION")
    doc.package.check_sum = Algorithm(identifier="SHA1", value="PROJECT_HASH?")

    doc.package.verif_code = "VERIF_CODE"
    doc.package.cr_text = "COPYRIGHT TEXT"
    doc.package.conc_lics = SPDXNone()
    doc.package.license_declared = SPDXNone()
    doc.package.licenses_from_files = [SPDXNone()]


def create_document():
    document = Document(name="REPORT_NAME",
                        namespace="NAMESPACE",
                        spdx_id="SPDXRef-DOCUMENT",
                        version=version.Version(2, 1),
                        data_license=License.from_identifier("CC0-1.0"))
    # Creation Info
    document.creation_info.set_created_now()
    document.creation_info.add_creator("CREATOR")

    return document


def create_sbom_doc(token: str):
    # init(token)

    doc = create_document()
    create_package(doc)
    create_files(doc)

    with open("spdx_out.json", "w") as fp:
        spdx_json.write_document(doc, fp)

    return doc


def create_header(doc):
    pass


def assign_spdx_lic_to_report(token: str):
    libs = ws_conn.get_licenses(token=token)
    for lib in libs:
        logging.debug(f"Working on library: {lib['name']}")
        for lic in lib['licenses']:
            # lookup_val = fix_license_id(lic['spdxName'])
            logging.debug(f"Searching for: {lic['spdxName']}")
            # logging.debug(f"Searching for: {lookup_val} (Original value: {lic['spdxName']})")
            try:
                lic['spdx_license_list'] = spdx_license_list.LICENSES[lic['spdxName']]
            except KeyError:
                logging.error(f"Could not find SPDX result for value: {lic['spdxName']}")

    return libs


if __name__ == '__main__':
    ret = create_sbom_doc(sys.argv[1])
    # inventory = ws_conn.get_inventory(token=sys.argv[1])
    # dd = ws_conn.get_due_diligence(token=sys.argv[1])

    logging.info("Done")
