import os
import platform

from twisted.internet import defer

import coind_data#, helper
import pack

P2P_PREFIX = 'fac3b6da'.decode('hex')
P2P_PORT = 12025
ADDRESS_VERSION = 30
RPC_PORT = 14023
# RPC_CHECK = defer.inlineCallbacks(lambda bitcoind: defer.returnValue(
#             (yield helper.check_block_header(bitcoind, '7497ea1b465eb39f1c8f507bc877078fe016d6fcb6dfad3a64c98dcc6e1e8496')) and # genesis block
#             (yield bitcoind.rpc_getmininginfo())['pow_algo'] == 'sha256d' and
#             (yield bitcoind.rpc_getblockchaininfo())['chain'] != 'test'
#         ))
SUBSIDY_FUNC = lambda height: __import__('digibyte_subsidy').GetBlockBaseValue(height)
POW_FUNC = lambda data: pack.IntType(256).unpack(__import__('ltc_scrypt').getPoWHash(data))
# POW_FUNC = coind_data.hash256
BLOCK_PERIOD = 150
SYMBOL = 'DGB'
CONF_FILE_FUNC = lambda: os.path.join(os.path.join(os.environ['APPDATA'], 'digibyte') if platform.system() == 'Windows' else os.path.expanduser('~/Library/Application Support/digibyte/') if platform.system() == 'Darwin' else os.path.expanduser('~/.digibyte'), 'digibyte.conf')
BLOCK_EXPLORER_URL_PREFIX = 'https://chainz.cryptoid.info/dgb/block.dws?'
ADDRESS_EXPLORER_URL_PREFIX = 'https://chainz.cryptoid.info/dgb/address.dws?'
TX_EXPLORER_URL_PREFIX = 'https://chainz.cryptoid.info/dgb/tx.dws?'
SANE_TARGET_RANGE = (2**256//2**33 - 1, 2**256//2**31 - 1)
DUMB_SCRYPT_DIFF = 2**16
DUST_THRESHOLD = 0.03e8

