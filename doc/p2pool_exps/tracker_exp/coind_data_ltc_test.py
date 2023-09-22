import coind_data_ltc
import pack


def bytes_to_data(bytes):
    res = b''
    for x in bytes:
        res += chr(x)
    return res  # str(res).replace(', ', ' ')


def data_to_bytes(data):
    return [ord(x) for x in data]


class PARENT_NETWORK:
    def __init__(self):
        self.SYMBOL = 'tLTC'
        self.ADDRESS_VERSION = 111
        self.ADDRESS_P2SH_VERSION = 58


class NETWORK:
    def __init__(self):
        self.PARENT = PARENT_NETWORK()


# _net = dict(
#     PARENT=dict(
#         SYMBOL='tLTC',
#         ADDRESS_VERSION=111,
#         ADDRESS_P2SH_VERSION=58
#     )
# )

_net = NETWORK()

# DONATION_SCRIPT = '522102d92234777b63f6dbc0a0382bbcb54e0befb01f6a4b062122fadab044af6c06882103b27bbc5019d3543586482a995e8f57c6ad506a4dafa6bf7cc89533b8dcb2df1b2102911ff87e792ec75b3a30dc115dfd06ec27c93b27034aa8e7cefbee6477e5d03453ae'.decode('hex')
DONATION_SCRIPT = '4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac'.decode(
    'hex')
print("DONATION_SCRIPT = {0}".format(data_to_bytes(DONATION_SCRIPT)))


def donation_script_to_address(net):
    try:
        return coind_data_ltc.script2_to_address(
            DONATION_SCRIPT, net.PARENT.ADDRESS_VERSION, -1, net.PARENT)
    except ValueError:
        return coind_data_ltc.script2_to_address(
            DONATION_SCRIPT, net.PARENT.ADDRESS_P2SH_VERSION, -1, net.PARENT)


print('donation_script_to_address = {0}'.format(donation_script_to_address(_net)))

addr_to_pubkey_hash = coind_data_ltc.address_to_pubkey_hash(donation_script_to_address(_net), _net.PARENT)
print('address_to_pubkey_hash = {0}; value = {1}'.format(addr_to_pubkey_hash, hex(addr_to_pubkey_hash[0])))

pubkey_hash_to_addr = coind_data_ltc.pubkey_hash_to_address(addr_to_pubkey_hash[0], _net.PARENT.ADDRESS_VERSION, -1, _net)
print('pubkey_hash_to_address = {0}'.format(pubkey_hash_to_addr))

