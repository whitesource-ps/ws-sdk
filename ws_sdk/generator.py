import argparse
import json
from distutils.util import strtobool
import logging
import os
import sys
from datetime import datetime

from ws_sdk import ws_constants, WS
from ws_sdk.app import WSApp
from ws_sdk._version import __version__
__tool_name__ = "WSG"
__description__ = "WhiteSource Runner"

is_debug = logging.DEBUG if bool(os.environ.get("DEBUG", 0)) else logging.INFO
logging.basicConfig(stream=sys.stdout, level=is_debug, format='%(levelname)s %(asctime)s %(thread)d %(name)s: %(message)s')

conf = None


def parse_args():
    def get_all_calls():
        return [func for func in dir(WSApp) if callable(getattr(WSApp, func)) and not func.startswith("__")]

    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('-u', '--userKey', help="WS User Key", dest='ws_user_key', type=str, required=True)
    parser.add_argument('-k', '--token', help="WS Token", dest='ws_token', type=str, required=True)
    parser.add_argument('-y', '--token_type', help="WS Token Type", dest='ws_token_type', choices=ws_constants.ScopeTypes.SCOPE_TYPES, required=True)
    parser.add_argument('-m', '--method', help="Method to run", type=str, choices=get_all_calls(), dest='method', required=True)
    parser.add_argument('-a', '--wsUrl', help="WS URL", dest='ws_url', type=str, default="saas")
    parser.add_argument('-o', '--reportDir', help="Report Dir", dest='dir', default="reports", type=str)
    parser.add_argument('-x', '--extraArguments', help="Extra arguments (key=value) to pass the report", dest='extra_args', type=str)

    return parser.parse_args()


def init():
    def get_extra_args(extra_args: str) -> dict:
        """
        Function to extract extra report argument and parse it to key value dictionary where value can be a string or a list (comma seperated).
        :param extra_args: string that of key=val or key=val1,val2...
        :return: dictionary
        """
        ret = {}
        if extra_args:
            extra_report_args_l = extra_args.split("=")

            report_args_val_l = extra_report_args_l[1].split(',')
            if len(report_args_val_l) == 1:
                try:
                    extra_report_args_l[1] = bool(strtobool(extra_report_args_l[1]))
                except ValueError:
                    logging.debug("Str")

            else:
                extra_report_args_l[1] = [value.strip() for value in report_args_val_l]
                t = bool(strtobool(extra_report_args_l[1]))

            ret = {extra_report_args_l[0]: extra_report_args_l[1]}
            logging.debug(f"Extra arguments passed to the report: {ret}")

        return ret

    global conf
    conf.extra_args_d = get_extra_args(conf.extra_args)


def main():
    global conf
    start_time = datetime.now()
    conf = parse_args()
    init()
    logging.info(f"Start running {__description__}, Version {__version__}")
    ws_conn = WS(user_key=conf.ws_user_key,
                 token=conf.ws_token,
                 url=conf.ws_url,
                 token_type=conf.ws_token_type)

    method = getattr(WS, conf.method)
    ret = method(ws_conn, **conf.extra_args_d)

    logging.info(f"output:\n {json.dumps(ret, default=str)}")

    logging.info(f"Finished running {__description__}. Run time: {datetime.now() - start_time}")


if __name__ == '__main__':
    main()
