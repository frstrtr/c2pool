#!/usr/bin/env python3
"""Capture a daemon-produced BIP 152 cmpctblock for a regtest block with mempool txs.

Generalised from ~/ltc-mweb-l2/capture_cmpct.py (the litecoind vector behind
ltc_regtest_cmpct_fixtures.hpp, c2pool PR #2058). Oracle = the coin daemon:
we only record what it sends. stdlib only. Prints one JSON object.

    capture_cmpct_vector.py btc     # Bitcoin Core (~/btc-golden-regtest/bitcoind)
    capture_cmpct_vector.py dgb     # DigiByte Core (~/digibyte-8.26.2/bin/digibyted)

Throwaway node: fresh datadir, private loopback ports, connect=0, stopped and
REMOVED afterwards. The shared regtest rigs (DGB :18566, LTC :19453, DOGE
:18332) are never touched. Refuses to run if the datadir already exists.
"""
import hashlib, json, os, random, shutil, socket, struct, subprocess, sys, time

PROFILES = {
    'btc': dict(
        bin=os.path.expanduser('~/btc-golden-regtest'),
        daemon='bitcoind', cli='bitcoin-cli', conf='bitcoin.conf',
        rpcport=18743, p2pport=18744,
        magic='fabfb5da',          # bitcoin regtest pchMessageStart
        proto=70016, services=1 | (1 << 3),   # NODE_NETWORK | NODE_WITNESS
        mine_tail=[],              # generatetoaddress nblocks addr
        extra_daemon_args=[],
    ),
    'dgb': dict(
        bin=os.path.expanduser('~/digibyte-8.26.2/bin'),
        daemon='digibyted', cli='digibyte-cli', conf='digibyte.conf',
        rpcport=18843, p2pport=18844,
        magic='fabfb5da',          # digibyte regtest pchMessageStart (kernel/chainparams.cpp CRegTestParams)
        proto=70017,               # DGB MIN_PEER_PROTO_VERSION = 70017
        services=1 | (1 << 3),
        mine_tail=['1000000', 'scrypt'],   # generatetoaddress nblocks addr maxtries algo
        extra_daemon_args=[],
    ),
}

MATURE_BLOCKS = 110   # > COINBASE_MATURITY (100; DGB 8 or 100 by height)
SENDS = (('bech32', '1.5'), ('bech32', '2.25'), ('legacy', '0.75'),
         ('p2sh-segwit', '3.1'), ('bech32', '0.42'), ('legacy', '5.0'))


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Node:
    def __init__(self, coin, P, datadir):
        self.coin, self.P, self.D = coin, P, datadir
        self.MAGIC = bytes.fromhex(P['magic'])

    def cli(self, *args):
        r = subprocess.run([f"{self.P['bin']}/{self.P['cli']}", f'-datadir={self.D}',
                            f"-conf={self.D}/{self.P['conf']}"] + list(args),
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f'cli {args}: {r.stderr.strip()}')
        return r.stdout.strip()

    def msg(self, cmd, payload=b''):
        return (self.MAGIC + cmd.encode().ljust(12, b'\0') + struct.pack('<I', len(payload))
                + sha256d(payload)[:4] + payload)

    def recv_msg(self, s):
        def read(n):
            b = b''
            while len(b) < n:
                c = s.recv(n - len(b))
                if not c:
                    raise EOFError
                b += c
            return b
        h = read(24)
        assert h[:4] == self.MAGIC, h[:4].hex()
        cmd = h[4:16].rstrip(b'\0').decode()
        ln = struct.unpack('<I', h[16:20])[0]
        p = read(ln)
        assert sha256d(p)[:4] == h[20:24]
        return cmd, p

    @staticmethod
    def netaddr(services, port):
        return (struct.pack('<Q', services) + b'\0' * 10 + b'\xff\xff'
                + bytes([127, 0, 0, 1]) + struct.pack('>H', port))

    def capture(self, block_hash_hex, announces):
        """Connect as a P2P peer, send sendcmpct(announces...), then
        getdata(MSG_CMPCT_BLOCK=4, hash); return the first cmpctblock/block."""
        P = self.P
        s = socket.create_connection(('127.0.0.1', P['p2pport']), timeout=20)
        services = P['services']
        ua = b'/cmpct-vector/'
        ver = (struct.pack('<iQq', P['proto'], services, int(time.time()))
               + self.netaddr(services, P['p2pport']) + self.netaddr(services, 0)
               + struct.pack('<Q', random.getrandbits(64)) + bytes([len(ua)]) + ua
               + struct.pack('<i', 0) + b'\x01')
        s.sendall(self.msg('version', ver))
        peer_services = peer_ua = None
        got_verack = False
        while not got_verack:
            cmd, p = self.recv_msg(s)
            if cmd == 'version':
                peer_services = struct.unpack('<Q', p[4:12])[0]
                ua_len = p[80]
                peer_ua = p[81:81 + ua_len].decode(errors='replace')
                s.sendall(self.msg('verack'))
            elif cmd == 'verack':
                got_verack = True
        for hb, v in announces:
            s.sendall(self.msg('sendcmpct', bytes([1 if hb else 0]) + struct.pack('<Q', v)))
        time.sleep(0.5)
        s.sendall(self.msg('getdata', b'\x01' + struct.pack('<I', 4) + bytes.fromhex(block_hash_hex)[::-1]))
        deadline = time.time() + 20
        seen = []
        while time.time() < deadline:
            cmd, p = self.recv_msg(s)
            seen.append(cmd)
            if cmd == 'ping':
                s.sendall(self.msg('pong', p))
            if cmd in ('cmpctblock', 'block'):
                s.close()
                return {'command': cmd, 'payload_hex': p.hex(), 'peer_services': peer_services,
                        'peer_user_agent': peer_ua,
                        'announced': [[hb, v] for hb, v in announces], 'messages_seen': seen}
        raise RuntimeError(f'no cmpctblock; saw {seen}')


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in PROFILES:
        raise SystemExit(__doc__)
    coin = sys.argv[1]
    P = PROFILES[coin]
    D = os.path.expanduser(f'~/siphash-2055-vec/{coin}')
    if os.path.exists(D):
        raise SystemExit(f'{D} exists; refusing to reuse a datadir')
    os.makedirs(D)
    with open(f"{D}/{P['conf']}", 'w') as f:
        f.write(f"regtest=1\nserver=1\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n"
                f"rpcport={P['rpcport']}\nport={P['p2pport']}\nbind=127.0.0.1\nlisten=1\n"
                f"rpcuser=vec\nrpcpassword=vec\nfallbackfee=0.0002\nmaxtxfee=100\n"
                f"dnsseed=0\nconnect=0\nlistenonion=0\n")
    node = Node(coin, P, D)
    cmdline = [f"{P['bin']}/{P['daemon']}", f'-datadir={D}', f"-conf={D}/{P['conf']}"] + P['extra_daemon_args']
    proc = subprocess.Popen(cmdline, stdout=open(f'{D}/stdout.log', 'w'), stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    out = {'coin': coin, 'daemon_cmdline': ' '.join(cmdline),
           'conf': open(f"{D}/{P['conf']}").read(),
           'captured_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    try:
        for _ in range(120):
            try:
                node.cli('getblockcount')
                break
            except Exception:
                time.sleep(0.5)
        ni = json.loads(node.cli('getnetworkinfo'))
        out['daemon_version'] = ni['subversion']
        out['daemon_protocolversion'] = ni['protocolversion']
        try:
            node.cli('createwallet', 'vec')
        except RuntimeError:
            # older wallet code: legacy wallet
            node.cli('createwallet', 'vec', 'false', 'false', '', 'false', 'false')
        coinbase_addr = node.cli('getnewaddress', '', 'bech32')
        out['coinbase_address'] = coinbase_addr
        node.cli('generatetoaddress', str(MATURE_BLOCKS), coinbase_addr, *P['mine_tail'])
        sends = []
        for kind, amt in SENDS:
            a = node.cli('getnewaddress', '', kind)
            sends.append({'kind': kind, 'address': a, 'amount': amt,
                          'txid': node.cli('sendtoaddress', a, amt)})
        out['sends'] = sends
        out['mempool_size'] = len(json.loads(node.cli('getrawmempool')))
        bh = json.loads(node.cli('generatetoaddress', '1', coinbase_addr, *P['mine_tail']))[0]
        blk = json.loads(node.cli('getblock', bh, '2'))
        out['block_hash'] = bh
        out['height'] = blk['height']
        out['header_hex'] = node.cli('getblockheader', bh, 'false')
        out['block_hex'] = node.cli('getblock', bh, '0')
        out['txs'] = [{'txid': t['txid'], 'wtxid': t['hash'], 'hex': t['hex']} for t in blk['tx']]
        out['softforks'] = json.loads(node.cli('getblockchaininfo')).get('softforks')
        out['captures'] = {
            # low-bandwidth v2 announce, then getdata(MSG_CMPCT_BLOCK)
            'v2': node.capture(bh, [(False, 2)]),
            # second connection, high-bandwidth v2: the daemon serves its cached
            # most-recent compact block (same nonce) or builds a fresh one
            'v2_hb': node.capture(bh, [(True, 2)]),
        }
    finally:
        try:
            node.cli('stop')
        except Exception:
            pass
        try:
            proc.wait(timeout=60)
        except Exception:
            proc.kill()
        shutil.rmtree(D, ignore_errors=True)
    print(json.dumps(out, indent=1))


main()
