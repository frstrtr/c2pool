# ASIO (Twisted and defer replacement)?
# LMDB or LevelDB database?
#   https://en.wikipedia.org/wiki/LevelDB
#   https://en.wikipedia.org/wiki/Lightning_Memory-Mapped_Database

# Web-server?
# Deferred requests?
# Bitcoin Core based design solutions
# ...


# STRATUM server and ports
# JSON-RPC client-server multi-core-wallet interface
# p2p interface
# http-server
# exchange interface
# multiSig wallets
# exchange API
# mining API
# Share storage/downloader
# fee calculations for mining reward
# fee calculations for low-difficulty infoshare submission
# fee calculations for node owners
# share/block verification
# infoshare softfork
# p2pool protocol emulator
# crypto module for popular algos
# merged mining


# Unlike Bitcoin, nodes do not know the entire chain - instead they only hold the last 8640 shares (the last 3 day's worth). In order to prevent an attacker from working on a chain in secret and then releasing it, overriding the existing chain, chains are judged by how much work they have since a point in the past. To ascertain that the work has been done since that point, nodes look at the Bitcoin blocks that the shares reference, establishing a provable timestamp. (If a share points to a block, it was definitely made after that block was made.)

# Payout logic
# Each share contains a generation transaction that pays to the previous n shares, where n is the number of shares whose total work is equal to 3 times the average work required to solve a block, or 8640 (= 72 hours of shares), whichever is smaller. Payouts are weighted based on the amount of work each share took to solve, which is proportional to the p2pool difficulty at that time.

# The block reward (currently 12.5BTC) and the transaction fees are combined and apportioned according to these rules:

# A subsidy of 0.5% is sent to the node that solved the block in order to discourage not sharing solutions that qualify as a block. (A miner with the aim to harm others could withhold the block, thereby preventing anybody from getting paid. He can NOT redirect the payout to himself.) The remaining 99.5% is distributed evenly to miners based on work done recently.

# In the event that a share qualifies as a block, this generation transaction is exposed to the Bitcoin network and takes effect, transferring each node its payout.

# Long polling
# Long polling is a method used by some Bitcoin pools by which notifications are sent to all miners when a valid block has been generated and added to the blockchain. This serves the purpose of stopping work on the old block and beginning to work on a fresh block, thus reducing the production of stale shares.

# Without long polling, if a miner was in the middle of an assigned workload when a new block was discovered by someone else, it would continue working on the old obsolete block solution until it was finished - thus wasting effort.
