import struct
import re

_bytes = ['c', 's', 'p']
_int = ['b', 'B', 'h', 'H', 'i', 'I', 'l', 'L', 'q', 'Q', 'n', 'N', 'P']
_bool = ['?']
_float = ['e', 'f', 'd']

def convert(type, val):
    if type in _bytes:
        return bytes(val, encoding = 'utf-8')
    if type in _int:
        return int(val)
    if type in _bool:
        return bool(int(val))
    if type in _float:
        return float(val)

def pack(types, args):
    """
    :param types: str, example: '<II'
    :param args: variables for pack, str
    :return: type = bytes
    """
    _t = re.sub('[@=<>!1234567890]','', types)
    vars = re.sub('[ ]', '', args).split(',')
    print(_t)
    print(vars)
    res = tuple(convert(type,var) for type, var in zip(_t,vars))
    print(res)
    return struct.pack(types, *res)

def unpack(types, var_bytes):
    """
    :param types: str, example: '<II'
    :param var_bytes: pack(types, <...>)
    :return: type = tuple
    """
    return  struct.unpack(types, var_bytes)


# def Test():
#     print(pack('<IIQ3s', '1, 2,3, asd'))
#
# Test()