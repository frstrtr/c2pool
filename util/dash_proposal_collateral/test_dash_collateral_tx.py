# Copyright (c) 2026 Alec <frstrtr@gmail.com>
# Distributed under the MIT software license.
"""Tests for dash_collateral_tx.py.

ALL key material here is the public BIP39 test mnemonic ("abandon ... about").
No real mnemonic, no real key, is used or needed anywhere in this suite.

The governance-hash vectors are LIVE MAINNET governance objects (public data),
captured 2026-08-19 from a mainnet Dash Core v22 node (`gobject list all proposals`),
including the on-chain OP_RETURN byte-order proof for object 5966468c... whose
collateral tx b74be348... carries script 6a2029113ef1... (internal byte order).
"""

import json

import pytest

import dash_collateral_tx as dct

DUMMY_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)

# Dummy-mnemonic BIP44 DASH external-chain addresses (m/44'/5'/0'/0/i)
DUMMY_ADDRS = [
    "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5",  # 0
    "XbctnEsgWTn5j1co3emZynemxSFPqkLRKZ",  # 1
    "XdD2biTJ3saZtcR6ravwJ9bvmkvmDq49Xg",  # 2
]

# ---------------------------------------------------------------------------
# Governance object hash -- live mainnet KATs
# ---------------------------------------------------------------------------
MAINNET_GOBJECT_VECTORS = [
    # (expected displayed hash, creation time, data hex)
    (
        "5966468c7703afe59d176277e289daa5836cd4131c1c488969852c2ff13e1129",
        1778694938,
        "7b22656e645f65706f6368223a313739333632353136302c226e616d65223a2232303236"
        "2d30352d4d616b6544617368415361666553746f72654f6656616c7565222c227061796d"
        "656e745f61646472657373223a2258744b41534a62313378724e45796933356244503472"
        "576744346d4a6236734d3264222c227061796d656e745f616d6f756e74223a312c227374"
        "6172745f65706f6368223a313739313034393638302c2274797065223a312c2275726c22"
        "3a2268747470733a2f2f7777772e6461736863656e7472616c2e6f72672f702f32303236"
        "2d30352d4d616b6544617368415361666553746f72654f6656616c7565227d"
    ),
    (
        "8576a3dbc52f93b8c333ed7398b592d569dbaa2d7647ea3e143f07c949034939",
        1779840000,
        "7b22656e645f65706f6368223a313739353532353230302c226e616d65223a2242544342"
        "61636b706f72747356696a61795f3033222c227061796d656e745f61646472657373223a"
        "2258707865386e7a3359386646655265676d57444168515a383435445574334d59546722"
        "2c227061796d656e745f616d6f756e74223a36302c2273746172745f65706f6368223a31"
        "3737393834303030302c2274797065223a312c2275726c223a2268747470733a2f2f7777"
        "772e6461736863656e7472616c2e6f72672f702f4254434261636b706f72747356696a61"
        "795f3033227d"
    ),
    (
        "5f4cf00613a36bb9683830204cdb4228c6ab665c5b12eb7451881d9315cc815e",
        1786624552,
        "7b226e616d65223a22707368656e6d69632d6465762d646173682d6465736b746f702d73"
        "657074656d6265722d32303236222c227061796d656e745f61646472657373223a22586a"
        "646e5a4255656446347138457a6757574147735a72487465456745557962626f222c2270"
        "61796d656e745f616d6f756e74223a3235302e30302c2275726c223a2268747470733a2f"
        "2f7777772e6461736863656e7472616c2e6f72672f702f707368656e6d69632d6465762d"
        "646173682d6465736b746f702d73657074656d6265722d32303236222c2273746172745f"
        "65706f6368223a313738353337383333382c22656e645f65706f6368223a313738373837"
        "303733382c2274797065223a317d"
    ),
]


class TestGovObjectHash:
    @pytest.mark.parametrize("expected,time_,data_hex", MAINNET_GOBJECT_VECTORS)
    def test_mainnet_kat(self, expected, time_, data_hex):
        h = dct.gov_object_hash("00" * 32, 1, time_, data_hex)
        assert h[::-1].hex() == expected

    def test_op_return_script_matches_chain(self):
        """Object 5966468c...'s on-chain collateral tx b74be348... carries
        script hex 6a2029113ef1...466659 -- internal byte order (verified against
        a mainnet node, getrawtransaction, 2026-08-19)."""
        expected, time_, data_hex = MAINNET_GOBJECT_VECTORS[0]
        h = dct.gov_object_hash("00" * 32, 1, time_, data_hex)
        script = dct.collateral_op_return_script(h)
        assert script.hex() == (
            "6a2029113ef12f2c856989481c1c13d46c83a5da89e27762179de5af03778c466659"
        )
        assert script[0] == 0x6A and script[1] == 0x20 and len(script) == 34

    def test_time_sensitivity(self):
        expected, time_, data_hex = MAINNET_GOBJECT_VECTORS[0]
        assert dct.gov_object_hash("00" * 32, 1, time_ + 1, data_hex)[::-1].hex() != expected

    def test_revision_sensitivity(self):
        expected, time_, data_hex = MAINNET_GOBJECT_VECTORS[0]
        assert dct.gov_object_hash("00" * 32, 2, time_, data_hex)[::-1].hex() != expected

    def test_bad_data_hex_aborts(self):
        with pytest.raises(dct.Abort):
            dct.gov_object_hash("00" * 32, 1, 1778694938, "zz")

    def test_bad_parent_aborts(self):
        with pytest.raises(dct.Abort):
            dct.gov_object_hash("00" * 30, 1, 1778694938, "aa")


# ---------------------------------------------------------------------------
# Base58 / address plumbing
# ---------------------------------------------------------------------------
class TestAddress:
    def test_roundtrip_mainnet(self):
        h160 = dct.addr_to_h160("XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", testnet=False)
        assert h160.hex() == "20cb5c22b1e4d5947e5c112c7696b51ad9af3c61"
        assert dct.h160_to_addr(h160, testnet=False) == "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u"

    def test_p2pkh_script(self):
        h160 = dct.addr_to_h160("XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", testnet=False)
        assert dct.p2pkh_script(h160).hex() == (
            "76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac"
        )

    def test_wrong_network_aborts(self):
        with pytest.raises(dct.Abort):
            dct.addr_to_h160("XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", testnet=True)

    def test_corrupt_checksum_aborts(self):
        with pytest.raises(dct.Abort):
            dct.addr_to_h160("XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84v", testnet=False)


# ---------------------------------------------------------------------------
# Key scan (dummy mnemonic only)
# ---------------------------------------------------------------------------
class TestKeyScan:
    def test_finds_index_2(self):
        priv, pub, path = dct.find_key_for_address(
            DUMMY_MNEMONIC, "", DUMMY_ADDRS[2], False, 0, 10, False
        )
        assert path == "m/44'/5'/0'/0/2"
        assert dct.h160_to_addr(dct.hash160(pub), False) == DUMMY_ADDRS[2]
        assert len(bytes(priv)) == 32
        dct._zeroize(priv)
        assert bytes(priv) == b"\x00" * 32

    def test_aborts_when_absent(self):
        # funding address NOT derivable from the dummy mnemonic
        with pytest.raises(dct.Abort, match="REFUSING TO SIGN"):
            dct.find_key_for_address(
                DUMMY_MNEMONIC, "", "XdgF55wEHBRWwbuBniNYH4GvvaoYMgL84u", False, 0, 50, True
            )

    def test_passphrase_changes_keys(self):
        with pytest.raises(dct.Abort):
            dct.find_key_for_address(
                DUMMY_MNEMONIC, "different-passphrase", DUMMY_ADDRS[0], False, 0, 5, False
            )

    def test_bad_mnemonic_checksum_rejected(self):
        bad = DUMMY_MNEMONIC.replace("about", "abandon")
        with pytest.raises(Exception):
            dct.find_key_for_address(bad, "", DUMMY_ADDRS[0], False, 0, 1, False)


# ---------------------------------------------------------------------------
# Coin selection
# ---------------------------------------------------------------------------
def mk_utxos(sats_list):
    return [
        {"txid": f"{i:064x}", "vout": 0, "satoshis": s, "confirmations": 200}
        for i, s in enumerate(sats_list)
    ]


class TestCoinSelection:
    def test_single_large_input(self):
        sel, fee, change = dct.select_coins(mk_utxos([2 * dct.COIN]), 1000, dct.TxBuilder())
        assert len(sel) == 1
        assert change == 2 * dct.COIN - dct.GOVERNANCE_PROPOSAL_FEE_TX - fee
        assert fee >= 1000

    def test_largest_first_multi(self):
        utxos = mk_utxos([30_000_000, 50_000_000, 10_000_000, 40_000_000, 5_000_000])
        sel, fee, change = dct.select_coins(utxos, 1000, dct.TxBuilder())
        picked = [u["satoshis"] for u in sel]
        assert picked == [50_000_000, 40_000_000, 30_000_000]  # largest first, 3 suffice
        assert sum(picked) == dct.GOVERNANCE_PROPOSAL_FEE_TX + fee + change

    def test_insufficient_aborts(self):
        with pytest.raises(dct.Abort, match="INSUFFICIENT FUNDS"):
            dct.select_coins(mk_utxos([90_000_000]), 1000, dct.TxBuilder())

    def test_dust_change_folds_into_fee(self):
        # total barely above 1 DASH + fee: change would be sub-dust
        utxos = mk_utxos([dct.GOVERNANCE_PROPOSAL_FEE_TX + 3000])
        sel, fee, change = dct.select_coins(utxos, 1000, dct.TxBuilder())
        assert change == 0
        assert fee == 3000  # entire remainder became fee, no dust output

    def test_conservation(self):
        utxos = mk_utxos([60_000_000, 45_000_000, 33_000_000])
        sel, fee, change = dct.select_coins(utxos, 2000, dct.TxBuilder())
        assert sum(u["satoshis"] for u in sel) == dct.GOVERNANCE_PROPOSAL_FEE_TX + fee + change


# ---------------------------------------------------------------------------
# UTXO normalization
# ---------------------------------------------------------------------------
FUND_SCRIPT = bytes.fromhex("76a91420cb5c22b1e4d5947e5c112c7696b51ad9af3c6188ac")


class TestNormalizeUtxos:
    def test_foreign_script_aborts(self):
        raw = [
            {
                "txid": "00" * 32,
                "vout": 0,
                "satoshis": 1000,
                "confirmations": 500,
                "scriptPubKey": "76a914" + "11" * 20 + "88ac",
            }
        ]
        with pytest.raises(dct.Abort, match="does NOT pay the funding"):
            dct.normalize_utxos(raw, FUND_SCRIPT, 101)

    def test_immature_skipped(self, capsys):
        raw = [
            {"txid": "00" * 32, "vout": 0, "satoshis": 1000, "confirmations": 5,
             "scriptPubKey": FUND_SCRIPT.hex()},
            {"txid": "11" * 32, "vout": 1, "satoshis": 2000, "confirmations": 500,
             "scriptPubKey": FUND_SCRIPT.hex()},
        ]
        out = dct.normalize_utxos(raw, FUND_SCRIPT, 101)
        assert len(out) == 1 and out[0]["satoshis"] == 2000

    def test_amount_fallback(self):
        raw = [{"txid": "22" * 32, "vout": 3, "amount": 0.5, "confirmations": 500}]
        out = dct.normalize_utxos(raw, FUND_SCRIPT, 101)
        assert out[0]["satoshis"] == 50_000_000

    def test_malformed_aborts(self):
        with pytest.raises(dct.Abort, match="malformed"):
            dct.normalize_utxos([{"txid": "xy", "vout": 0}], FUND_SCRIPT, 101)


# ---------------------------------------------------------------------------
# Transaction build + sign (dummy key), full structural round-trip
# ---------------------------------------------------------------------------
def parse_tx(raw: bytes):
    """Minimal independent legacy-tx parser used to round-trip our serializer."""
    off = 0

    def u32():
        nonlocal off
        v = int.from_bytes(raw[off : off + 4], "little")
        off += 4
        return v

    def cs():
        nonlocal off
        b0 = raw[off]
        off += 1
        if b0 < 0xFD:
            return b0
        n = {0xFD: 2, 0xFE: 4, 0xFF: 8}[b0]
        v = int.from_bytes(raw[off : off + n], "little")
        off += n
        return v

    tx = {"version": u32(), "inputs": [], "outputs": []}
    for _ in range(cs()):
        txid = raw[off : off + 32][::-1].hex()
        off += 32
        vout = u32()
        slen = cs()
        script = raw[off : off + slen]
        off += slen
        seq = u32()
        tx["inputs"].append({"txid": txid, "vout": vout, "script": script, "seq": seq})
    for _ in range(cs()):
        value = int.from_bytes(raw[off : off + 8], "little")
        off += 8
        slen = cs()
        script = raw[off : off + slen]
        off += slen
        tx["outputs"].append({"value": value, "script": script})
    tx["locktime"] = u32()
    assert off == len(raw), "trailing bytes"
    return tx


def build_signed_dummy_tx():
    priv, pub, _ = dct.find_key_for_address(
        DUMMY_MNEMONIC, "", DUMMY_ADDRS[0], False, 0, 3, False
    )
    fund_script = dct.p2pkh_script(dct.addr_to_h160(DUMMY_ADDRS[0], False))
    gov = dct.gov_object_hash("00" * 32, 1, 1778694938, MAINNET_GOBJECT_VECTORS[0][2])
    txb = dct.TxBuilder()
    txb.add_input("aa" * 32, 1, fund_script, 70_000_000)
    txb.add_input("bb" * 32, 0, fund_script, 40_000_000)
    txb.add_output(dct.GOVERNANCE_PROPOSAL_FEE_TX, dct.collateral_op_return_script(gov))
    txb.add_output(9_990_000, fund_script)
    priv_b = bytes(priv)
    for i in range(2):
        digest = txb.sighash(i)
        der = dct.sign_digest(priv_b, digest)
        assert dct.verify_digest(pub, der, digest)
        txb.sigs[i] = (der + bytes([dct.SIGHASH_ALL]), pub)
    dct._zeroize(priv)
    return txb, pub


class TestTransaction:
    def test_structure_roundtrip(self):
        txb, pub = build_signed_dummy_tx()
        tx = parse_tx(txb.serialize(signed=True))
        assert tx["version"] == 2 and tx["locktime"] == 0
        assert len(tx["inputs"]) == 2 and len(tx["outputs"]) == 2
        assert tx["inputs"][0]["txid"] == "aa" * 32 and tx["inputs"][0]["vout"] == 1
        assert all(i["seq"] == 0xFFFFFFFF for i in tx["inputs"])
        # output 0: exactly 1 DASH to OP_RETURN <32 bytes>
        assert tx["outputs"][0]["value"] == 100_000_000
        s0 = tx["outputs"][0]["script"]
        assert s0[0] == 0x6A and s0[1] == 32 and len(s0) == 34
        assert s0[2:].hex() == (
            "29113ef12f2c856989481c1c13d46c83a5da89e27762179de5af03778c466659"
        )
        # output 1: P2PKH change
        assert tx["outputs"][1]["script"][:3] == bytes([0x76, 0xA9, 20])

    def test_scriptsig_layout_and_lows(self):
        txb, pub = build_signed_dummy_tx()
        tx = parse_tx(txb.serialize(signed=True))
        for i, inp in enumerate(tx["inputs"]):
            script = inp["script"]
            sig_len = script[0]
            sig = script[1 : 1 + sig_len]
            assert sig[-1] == dct.SIGHASH_ALL
            assert dct._der_is_low_s(sig[:-1])
            pub_len = script[1 + sig_len]
            assert script[2 + sig_len : 2 + sig_len + pub_len] == pub
            assert len(script) == 2 + sig_len + pub_len

    def test_signature_binds_outputs(self):
        """Mutating an output invalidates every signature (SIGHASH_ALL)."""
        txb, pub = build_signed_dummy_tx()
        d0 = txb.sighash(0)
        txb.outputs[1]["value"] += 1
        assert txb.sighash(0) != d0

    def test_txid_deterministic(self):
        a, _ = build_signed_dummy_tx()
        b, _ = build_signed_dummy_tx()
        assert a.txid() == b.txid()  # RFC6979: fully deterministic signing

    def test_size_estimate_covers_actual(self):
        txb, _ = build_signed_dummy_tx()
        actual = len(txb.serialize(signed=True))
        est = txb.estimate_size(2, with_change=True)
        assert actual <= est <= actual + 8  # worst-case estimate, never below actual


class TestLowS:
    def test_rejects_high_s(self):
        # hand-build a DER sig with s > n/2
        r = (1).to_bytes(32, "big")
        s = (dct.SECP256K1_N - 1).to_bytes(33, "big").lstrip(b"\x00")
        s = b"\x00" + s if s[0] & 0x80 else s
        body = b"\x02" + bytes([len(r)]) + r + b"\x02" + bytes([len(s)]) + s
        der = b"\x30" + bytes([len(body)]) + body
        assert not dct._der_is_low_s(der)
