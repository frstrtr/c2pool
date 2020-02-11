import struct

def pack(types, *args):
'''
types - str, example: '<II'
args - variables for pack
return - type(bytes)
'''
    return struct.pack(types, *args)

def unpack(types, var_bytes):
'''
types - str, example: '<II'
var_bytes - pack(types, <...>)
return - typle
'''
    return  struct.unpack(types, var_bytes)