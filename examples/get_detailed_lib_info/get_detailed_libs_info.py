import json
import logging
import os
import sys

from ws_sdk.web import WS

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

ws_url = os.environ['WS_URL']
ws_org_token = os.environ['WS_ORG_TOKEN']
ws_user_key = os.environ['WS_USER_KEY']


if __name__ == '__main__':
    try:
        input_file = open(sys.argv[1], 'r')
        input_libs = json.loads(input_file.read())
    except json.JSONDecodeError or FileNotFoundError:
        logging.exception("Unable to read input json")
        exit(-1)

    c_org = WS(url=ws_url, user_key=ws_user_key, token=ws_org_token)

    detailed_libs_list = []
    for lib in input_libs:
        res_libs = c_org.get_libraries(search_value=lib['library'], version=lib['version'])

        for res_lib in res_libs:
            results = c_org.get_library_detailed(name=res_lib['artifactId'],
                                                 version=res_lib['version'],
                                                 lib_type=res_lib['type'],
                                                 languages=res_lib.get('language'))
            detailed_libs_list.append(results)

    output_file = open(sys.argv[1].replace(".json", "_out.json") + ".", 'w')
    output_file.write(json.dumps(detailed_libs_list))
    output_file.close()
