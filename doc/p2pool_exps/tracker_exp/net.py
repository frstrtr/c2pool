import parent_net as _net

PARENT = _net
SHARE_PERIOD = 25
CHAIN_LENGTH = 24*60*60//10
REAL_CHAIN_LENGTH = 24*60*60//10
TARGET_LOOKBEHIND = 200
SPREAD = 30
IDENTIFIER = '83e65d2c81bf6d66'.decode('hex')
PREFIX = '83e65d2c81bf6d68'.decode('hex')
P2P_PORT = 5026
MIN_TARGET = 0
MAX_TARGET = 2**256//2**20 - 1
PERSIST = True
WORKER_PORT = 5027
BOOTSTRAP_ADDRS = 'crypto.office-on-the.net p2p-spb.xyz 46.188.44.20 siberia.mine.nu gigablock.mine.nu tomsk.mine.nu 45.32.210.32 triplezen.tk'.split(' ')
ANNOUNCE_CHANNEL = '#p2pool'
VERSION_CHECK = lambda v: None if 7170200 <= v else 'DigiByte version too old. Upgrade to 7.17.2 or newer!'
VERSION_WARNING = lambda v: None
SOFTFORKS_REQUIRED = set(['nversionbips', 'csv', 'segwit', 'reservealgo', 'odo'])
MINIMUM_PROTOCOL_VERSION = 1600
NEW_MINIMUM_PROTOCOL_VERSION = 1700
SEGWIT_ACTIVATION_VERSION = 17
BLOCK_MAX_SIZE = 1000000
BLOCK_MAX_WEIGHT = 4000000
