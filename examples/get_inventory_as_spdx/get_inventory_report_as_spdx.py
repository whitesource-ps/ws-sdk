import json
import logging
import os
import sys
from ws_sdk.web import WS
import spdx_license_list


logging.basicConfig(level=logging.DEBUG,
                    stream=sys.stdout,
                    format='%(levelname)s %(asctime)s %(thread)d: %(message)s',
                    datefmt='%y-%m-%d %H:%M:%S')


def fix_license_id(license_name: str):
    return license_name.replace(" ", "-") \
                       .replace("Classpath", "with-classpath-exception") \
                       .replace("Bison", "with-bison-exception") \
                       .replace("Autoconf", "with-autoconf-exception") \
                       .replace("Font", "with-font-exception") \
                       .replace("GCC", "with-GCC-exception")


if __name__ == '__main__':
    ws_url = os.environ['WS_URL']
    ws_org_token = os.environ['WS_ORG_TOKEN']
    ws_user_key = os.environ['WS_USER_KEY']
    ws_conn = WS(url=ws_url, user_key=ws_user_key, token=ws_org_token)
    # inventory = ws_conn.get_inventory(token=sys.argv[1])
    # dd = ws_conn.get_due_diligence(token=sys.argv[1])
    libs = ws_conn.get_licenses(token=sys.argv[1])
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

    print(json.dumps(libs))
    logging.info("Done")
