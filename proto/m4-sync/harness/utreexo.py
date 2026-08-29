#!/usr/bin/env python3
"""M4 core: a real Utreexo-style forest accumulator (add / prove / verify / delete).

The superlight-chain open problem: verifiers are stateless, but SOMEONE (a bridge
node) must hold the full O(n) forest to GENERATE membership proofs, and adversarial
churn (add+delete cycling) can inflate the proofs a verifier must carry. This module
is the bridge-node side: it holds every node hash so it can serve O(log n) proofs.

Forest = a list of perfect binary merkle trees, at most one per height, indexed by
the set bits of the leaf count `n` (classic Utreexo). Add merges equal-height trees;
delete swaps the target with the forest's last leaf then collapses, Utreexo-style.

Deterministic: hashing is sha256, no randomness, no wall-clock in the data path.
"""
from __future__ import annotations
import hashlib
from typing import Optional


def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def parent_hash(left: bytes, right: bytes) -> bytes:
    # domain-separate internal nodes from leaves to block second-preimage games
    return H(b"\x01", left, right)


def leaf_hash(data: bytes) -> bytes:
    return H(b"\x00", data)


class Forest:
    """Bridge-node forest: full node storage, proof generation, deletion."""

    def __init__(self) -> None:
        # rows[r][i] = hash of the i-th node at height r (row 0 = leaves)
        self.rows: list[list[bytes]] = [[]]
        self.leaf_index: dict[bytes, int] = {}  # leaf hash -> position in row 0

    @property
    def n(self) -> int:
        return len(self.rows[0])

    def _ensure_row(self, r: int) -> None:
        while len(self.rows) <= r:
            self.rows.append([])

    def _recompute_from(self, pos0: int) -> None:
        """Rebuild internal nodes on the path from leaf position pos0 to its roots."""
        pos = pos0
        r = 0
        while True:
            self._ensure_row(r + 1)
            sib = pos ^ 1
            # only fold when both children of this parent exist (perfect subtree)
            if sib < len(self.rows[r]):
                left = self.rows[r][pos & ~1]
                right = self.rows[r][pos | 1]
                ph = parent_hash(left, right)
                ppos = pos >> 1
                if ppos < len(self.rows[r + 1]):
                    if self.rows[r + 1][ppos] == ph:
                        return  # nothing changed upward
                    self.rows[r + 1][ppos] = ph
                else:
                    self.rows[r + 1].append(ph)
                pos = ppos
                r += 1
            else:
                return

    def add(self, data: bytes) -> bytes:
        return self.add_hash(leaf_hash(data))

    def add_hash(self, lh: bytes) -> bytes:
        """Append an already-computed leaf hash (snapshot/wire rebuild path).

        A snapshot ships leaf HASHES, not preimages; a sovereign rebuilding from
        the bridge's row-0 vector must fold them in the exact physical order to
        reproduce the committed roots."""
        pos0 = len(self.rows[0])
        self.rows[0].append(lh)
        self.leaf_index[lh] = pos0
        # fold upward greedily while we complete perfect subtrees
        pos, r = pos0, 0
        while pos & 1:  # has a left sibling at this height -> can merge
            self._ensure_row(r + 1)
            left = self.rows[r][pos - 1]
            right = self.rows[r][pos]
            ph = parent_hash(left, right)
            ppos = pos >> 1
            if ppos < len(self.rows[r + 1]):
                self.rows[r + 1][ppos] = ph
            else:
                self.rows[r + 1].append(ph)
            pos = ppos
            r += 1
        return lh

    def roots(self) -> list[bytes]:
        """Forest roots, one per set bit of n (the stateless verifier commitment)."""
        out: list[bytes] = []
        for r in range(len(self.rows)):
            row = self.rows[r]
            # a root at row r is the last node of a complete perfect tree of height r
            if (self.n >> r) & 1:
                # index of that root = (count of leaves in higher trees folded) ...
                # simpler: the root is row[r][-1] when this height carries a tree
                if row:
                    out.append(row[-1])
        return out

    def prove(self, lh: bytes) -> Optional[dict]:
        """Membership proof for a leaf: its position + sibling path (O(log n) hashes)."""
        pos0 = self.leaf_index.get(lh)
        if pos0 is None:
            return None
        path: list[bytes] = []
        pos, r = pos0, 0
        while True:
            sib = pos ^ 1
            if sib < len(self.rows[r]):
                path.append(self.rows[r][sib])
                pos >>= 1
                r += 1
            else:
                break
        return {"pos": pos0, "leaf": lh, "path": path, "tree_height": r}

    @staticmethod
    def verify(root: bytes, proof: dict) -> bool:
        """Stateless verification: recompute the root from leaf + sibling path."""
        acc = proof["leaf"]
        pos = proof["pos"]
        for sib in proof["path"]:
            if pos & 1:
                acc = parent_hash(sib, acc)
            else:
                acc = parent_hash(acc, sib)
            pos >>= 1
        return acc == root

    def node_count(self) -> int:
        return sum(len(r) for r in self.rows)

    # -- in-place swap-delete (T5) --------------------------------------------
    # This representation is FULLY-PACKED: row r holds floor(n/2^r) nodes, and
    # rows[r][i] == parent_hash(rows[r-1][2i], rows[r-1][2i+1]). So a delete is:
    # move the last leaf into the hole, pop the tail, and refold ONLY the hole's
    # ancestor spine while truncating each row to its new length. O(log n) hashes
    # per delete -- the realistic incremental bridge cost T4 could only bracket.

    def _refold_above(self, col: int) -> None:
        """Recompute the ancestor spine of leaf column `col` and truncate each
        row to floor(n/2^r), popping tail parents the leaf removal invalidated."""
        ar, r = col, 0
        while True:
            need = len(self.rows[r]) // 2  # target len of row r+1
            if need == 0:
                # no parents above this row: drop any stale higher rows
                del self.rows[r + 1:]
                break
            self._ensure_row(r + 1)
            nr = self.rows[r + 1]
            while len(nr) > need:  # pop tail parents (removed leaf's spine)
                nr.pop()
            par = ar >> 1
            if par < need:  # recompute the hole's ancestor at this level
                ph = parent_hash(self.rows[r][2 * par], self.rows[r][2 * par + 1])
                if par < len(nr):
                    nr[par] = ph
                else:
                    nr.append(ph)
            ar = par
            r += 1

    def delete(self, lh: bytes) -> bool:
        """In-place Utreexo-style deletion: swap the target with the last leaf,
        truncate, and refold the affected spine. Returns False if not present."""
        p = self.leaf_index.get(lh)
        if p is None:
            return False
        last = self.n - 1
        del self.leaf_index[lh]
        if p != last:
            moved = self.rows[0][last]
            self.rows[0][p] = moved
            self.leaf_index[moved] = p
        self.rows[0].pop()  # drop the tail leaf slot
        if self.n == 0:
            self.rows = [[]]
            self.leaf_index.clear()
            return True
        self._refold_above(min(p, self.n - 1))
        return True
