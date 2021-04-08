import logging
import os
import sys
import getpass
import argparse
from ws_sdk.web import WS
from ws_sdk import ws_utilities
from spdx.document import Document, License
from spdx.writers import json as spdx_json
from spdx import file, package, version, config, creationinfo
from spdx.utils import NoAssert, SPDXNone
from spdx.checksum import Algorithm
from datetime import datetime
from spdx.config import LICENSE_MAP, EXCEPTION_MAP

logging.basicConfig(level=logging.DEBUG,
                    stream=sys.stdout,
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')

args = ws_conn = None


def init():
    global ws_conn
    ws_conn = WS(url=args.ws_url, user_key=args.ws_user_key, token=args.ws_org_token)


def create_sbom_doc():
    global ws_conn, args
    init()
    scope = ws_conn.get_scope_by_token(args.scope_token)
    logging.debug(f"Starting to work on SBOM Document of {scope['type']} {scope['name']} (token: {args.scope_token})")
    doc = create_document(args.scope_token)
    doc.package = create_package(args.scope_token)
    doc.package.files, licenses_from_files, copyrights_from_files = create_files(args.scope_token)

    # After file section creation
    doc.package.verif_code = doc.package.calc_verif_code()
    doc.package.licenses_from_files = licenses_from_files
    doc.package.cr_text =  ', '.join(copyrights_from_files)
    write_file(doc, args.type)


def create_document(token: str) -> Document:
    logging.debug(f"Creating SBOM Document section")
    global ws_conn
    scope_name = ws_conn.get_scope_name_by_token(token)
    document = Document(name=f"WhiteSource {scope_name} SBOM report",
                        namespace=f"http://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]",    # UNKNOWN FROM WS
                        spdx_id="SPDXRef-DOCUMENT",
                        version=version.Version(2, 2),
                        data_license=License.from_identifier("CC0-1.0"))

    logging.debug(f"Creating SBOM Creation Info section")
    document.creation_info.set_created_now()
    org = creationinfo.Organization(ws_conn.get_organization_name(), "OPT_EMAIL")   # UNKNOWN FROM WS
    tool = creationinfo.Tool("White Source SBOM Report Generator")
    person = creationinfo.Person(getpass.getuser(), "OPT_EMAIL")                    # UNKNOWN FROM WS MAYBE FROM OS
    document.creation_info.add_creator(org)
    document.creation_info.add_creator(tool)
    document.creation_info.add_creator(person)

    logging.debug(f"Finished SBOM Document section")

    return document


def create_package(token: str) -> package.Package:
    logging.debug(f"Creating SBOM package section")
    global ws_conn
    pkg = package.Package(name=ws_conn.get_scope_name_by_token(token),
                              spdx_id="SPDXRef-PACKAGE-1",
                              download_location=SPDXNone())                         # UNKNOWN FROM WS
    pkg.check_sum = Algorithm(identifier="SHA1", value="")                          # UNKNOWN FROM WS
    pkg.cr_text = NoAssert()                                                        # UNKNOWN FROM WS
    pkg.conc_lics = NoAssert()                                                      # UNKNOWN FROM WS
    pkg.license_declared = NoAssert()                                               # UNKNOWN FROM WS
    logging.debug(f"Finished SBOM package section")

    return pkg


def create_files(scope_token: str):
    files = []
    all_licenses_from_files = set()
    all_copyright_from_files = set()
    dd_list = ws_conn.get_due_diligence(token=scope_token)
    dd_dict = ws_utilities.convert_dict_list_to_dict(lst=dd_list, key_desc=('library', 'name'))
    libs = ws_conn.get_licenses(token=scope_token)
    all_licenses_f2i = {**LICENSE_MAP, **EXCEPTION_MAP}
    all_licenses_i2f = {i:f for f,i in all_licenses_f2i.items()}                       # Inversing dictionary

    for i, lib in enumerate(libs):
        logging.debug(f"Handling library: {lib['name']}")
        spdx_file = file.File(name=lib['filename'],
                              spdx_id=f"SPDXRef-FILE-{i+1}",
                              chk_sum=Algorithm(identifier="SHA1", value=lib['sha1']))
        spdx_file.comment = lib['description']
        spdx_file.type = set_file_type(lib['type'], lib['filename'])

        file_license_copyright = set()
        for lic in lib['licenses']:
            # Handling license
            try:
                license_full_name = all_licenses_i2f[lic['spdxName']]
                logging.debug(f"Found license: {license_full_name}")
            except KeyError:
                logging.error(f"License with identifier: {lic['spdxName']} was not found")
                license_full_name = lic['spdxName']

            spdx_license = License(license_full_name, lic['spdxName'])
            all_licenses_from_files.add(spdx_license)
            spdx_file.licenses_in_file.append(spdx_license)

            # Handling Copyright license
            try:
                license_copyright = f"{lic['spdxName']} - {dd_dict[(lib['filename'], lic['name'])]['copyright']}"
                all_copyright_from_files.add(license_copyright)
                file_license_copyright.add(license_copyright)
                logging.debug(f"Found copyright: {license_copyright}")
            except KeyError:
                license_copyright = None
                logging.error(f"Copyright of : ({lib['filename']}, {lic['name']}) was not found")

        spdx_file.copyright =  ', '.join(file_license_copyright) if file_license_copyright else SPDXNone()
        spdx_file.conc_lics = SPDXNone()

        files.append(spdx_file)

    return files, all_licenses_from_files, all_copyright_from_files


def set_file_type(file_type: str, filename: str):       # TODO ADDITIONAL TESTINGS
    if file_type == "Source Files":
        ret = file.FileType.SOURCE
    elif filename.endswith((".jar", ".zip", ".tar", ".gz", ".tgz")):         # TODO COMPILE LIST
        logging.debug(f"Type of file: {filename} is binary")
        ret = file.FileType.ARCHIVE
    elif False:                                                               # TODO SEE IF WE CAN DISCOVER BINARIES
        logging.debug(f"Type of file: {filename} is binary")
        ret = file.FileType.BINARY
    else:
        logging.warning(f"File Type of {file_type} did not match")
        ret = file.FileType.OTHER

    return ret


def write_file(doc: Document, type):
    report_file = f"{doc.name}-{doc.version}.{get_suffix(type)}"
    logging.debug(f"Writing file: {report_file}")
    with open(report_file, "w") as fp:
        spdx_json.write_document(doc, fp)


def get_suffix(type: str):                                                   # TODO FINISH THIS
    return "json"


def parse_args():
    parser = argparse.ArgumentParser(description='Utility to create SBOM from WhiteSource data')
    parser.add_argument('-u', '--userKey', help="WSS User Key", dest='ws_user_key', required=True)
    parser.add_argument('-o', '--orgToken', help="WSS Organization Key", dest='ws_org_token', required=True)
    parser.add_argument('-p', '--scope', help="Scope token of SBOM report to generate", dest='scope_token', required=True)
    parser.add_argument('-a', '--wsUrl', help="WSS URL", dest='ws_url', required=True)
    parser.add_argument('-t', '--type', help="Output type (tv, json, rdf, yaml)", dest='type', default='json')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    create_sbom_doc()
    logging.info("Done")
