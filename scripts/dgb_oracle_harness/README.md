# DGB python-oracle harness

Runs shares minted by c2pool-dgb through the python DGB network's own code
(frstrtr/p2pool-dgb-scrypt 22761e7: `Share.check` and `generate_transaction`).
The oracle must accept every share, and the generation transaction bytes must
match c2pool's. Every mutated share (wrong max_bits, bits outside the clip
range, timestamp) must be rejected by both implementations.

1. Vectors (C++, part of `dgb_work_source_test`; writes only when asked):

       DGB_ORACLE_VECTORS=/path/vectors.json \
         build_dgb/src/impl/dgb/test/dgb_work_source_test --gtest_filter='DgbOracleVectors.*'

   The chain is genesis-rooted with 130 V35 shares, minted through the real
   producer, stratum job, mining_submit and mint. It has 400 s and 5000 s gaps,
   D/S/dgb1 payouts with equal-amount ties, and a dgb1q program with a leading
   zero byte.

2. Oracle check (python 2.7 + twisted, not in CI):

       python2 scripts/dgb_oracle_harness/check_vectors.py ORACLE_DIR /path/vectors.json

   ORACLE_DIR is a read-only checkout of the oracle (its root is the `p2pool`
   package). The last line is `RESULT PASS|FAIL ...`; the exit status is 0 on
   PASS.

PoW is not under test: the checker replaces `POW_FUNC` with 0, because the
vectors are not mined.

3. The python -> c2pool direction (python 2.7 + twisted, not in CI):

       python2 scripts/dgb_oracle_harness/mint_vectors.py ORACLE_DIR /path/py-vectors.json
       DGB_ORACLE_PY_VECTORS=/path/py-vectors.json \
         build_dgb/src/impl/dgb/test/dgb_work_source_test --gtest_filter='DgbOracleReverse.*'

   mint_vectors.py builds 130 V35 shares with the oracle's own
   generate_transaction / get_share on a genesis-rooted tracker, checks each
   with Share.check, and rotates the payout through every case python
   accepts: base58 P2PKH and P2SH, lowercase and UPPERCASE bech32, witness v1
   with the same program, 32- and 31-byte programs with a leading 0x00, and
   the donation's own P2PKH. Its negatives are valid shares mutated so python
   refuses them (a whitespace or trailing-newline address, the segwit_data
   none-value, far_share_hash / absheight / abswork); each refusal is checked
   in python. The C++ side verifies every share with python's hash and must
   refuse every negative; it prints `[oracle-reverse] RESULT PASS|FAIL ...`.

The vm905 environment: ~/dgb-oracle-env/py27 (micromamba 1.5.10; conda-forge
python 2.7.15 + pip, twisted 20.3.0 from pip: conda-forge has none for py27).
`check_vectors.py` sets p2pool.DEBUG / p2pool.BENCH, which the oracle's
main.py would set.
