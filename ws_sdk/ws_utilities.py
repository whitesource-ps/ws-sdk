import logging
def is_token(token: str) -> bool:
    return True if len(token) == 64 and token.isalnum() else False

def convert_dict_list_to_dict(lst: list,
                              key_desc: str or tuple) -> dict:
    """
    Function to convert list of dictionaries into dictionary of dictionaries according to specified key
    :param lst: List of dictionaries
    :param key_desc: the key or keys (as tuple) description of the returned dictionary
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
                    ret.append(dct[x])
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
