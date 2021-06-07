import logging

from . import ws_constants


def is_token(token: str) -> bool:
    return True if len(token) == 64 and token.isalnum() else False


def convert_dict_list_to_dict(lst: list,
                              key_desc: str or tuple) -> dict:
    """
    Function to convert list of dictionaries into dictionary of dictionaries according to specified key
    :param lst: List of dictionaries
    :param key_desc: the key or keys (as tuple) description of the returned dictionary (a key can be str or dict)
    :return: dict with key according to key description and the dictionary value
    """
    def create_key(key_desc: str or tuple,
                   dct: dict) -> str or tuple:
        ret = None
        if isinstance(key_desc, str):
            return dct[key_desc]
        elif isinstance(key_desc, tuple):
            ret = []
            for x in key_desc:
                try:
                    if isinstance(x, str) and dct[x]:
                        ret.append(dct[x])
                        logging.debug(f"Key type is a string: {dct[x]}")
                    elif isinstance(x, dict):
                        for key, value in x.items():
                            logging.debug(f"Key type is a dict: {key}")
                            internal_dict = dct.get(key, None)
                            if internal_dict:
                                ret.append(internal_dict.get(value, None))
                except KeyError:
                    logging.error(f"Key: {key_desc} was not found")
                    return None
            logging.debug(f"Key is tuple: {ret}")
            return tuple(ret)
        else:
            logging.error(f"Unsupported key_desc: {type(key_desc)}")
            return None

    ret = {}
    for i in lst:
        curr_key = create_key(key_desc, i)
        ret[curr_key] = i

    return ret


def get_all_req_schemas(ws_conn) -> dict:
    supported_requests = ws_conn.__generic_get__(get_type="SupportedRequests", token_type="")['supportedRequests']
    req_schema_list = {}
    for req in supported_requests:
        req_schema = ws_conn.__generic_get__(get_type="RequestSchema", token_type="", kv_dict={"request": req})
        req_schema_list[req] = req_schema

    return req_schema_list


def get_report_types():
    from ws_sdk import web
    report_types = set()
    class_dict = dict(web.WS.__dict__)
    for f in class_dict.items():
        if web.report_metadata.__name__ in str(f[1]):
            report_types.add(f[0].replace('get_',''))

    return report_types


def get_lib_metadata_by_name(language: str) -> ws_constants.LibMetaData.LibMetadata:
    """
    Method that Returns matadata on a language
    :type language: language to return metadata on
    :rtype: NamedTuple
    """
    lc_lang = language.lower()
    for lang_metadata in ws_constants.LibMetaData.L_TYPES:
        if lang_metadata.language == lc_lang:
            return lang_metadata
    logging.error("Language is unsupported")

    return None


def get_package_managers_by_language(language: str) -> list:
    lang_md = get_lib_metadata_by_name(language=language)

    return lang_md.package_manager if lang_md else None
