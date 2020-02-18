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

    print(args)

    buff = str()
    res = str()
    for i in types:
        if i.isnumeric():
            buff += i
        else:
            if not i in _bytes:
                if buff:
                    res += int(buff)*i
                else:
                    res += i
            else:
                res += buff+i
            buff = ''


    _t = re.sub('[@=<>!1234567890]','', res)
    vars = re.sub('[ ]', '', args).split(',')
    res = tuple(convert(type,var) for type, var in zip(_t,vars))
    return struct.pack(types, *res)

def unpack(types, var_bytes):
    """
    :param types: str, example: '<II'
    :param var_bytes: pack(types, <...>)
    :return: type = str stream [tuple]
    """


    res = str(struct.unpack(types, var_bytes))
    res = re.sub('[,()]', '', res)
    return res


# def Test():
#     print(pack('<IIQ3s', '1, 2,3, asd'))
#
# Test()