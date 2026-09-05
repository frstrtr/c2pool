#!/usr/bin/env python3
"""
V37 P5 integration — PORTS + late-binding slice registry.

P5 composes the already-verified V37 slices into ONE end-to-end node lifecycle. Per the
milestone-sequencing bound (integrator 2026-07-02): this is INTERFACE-LEVEL scaffolding, held
no-push. It must NOT hard-couple to the exact unmerged slice SHAs (golden d659c801, stamp
39f96135, ...) so the batched merge-cp is a drop-in, not a rebase storm.

Mechanism: each slice is reached through a narrow PORT (an abstract contract). P5 ships a
reference STUB adapter per port that mirrors the slice's *public surface* only — enough to
exercise the cross-layer invariants. At merge-cp each stub is swapped for a thin real adapter
that forwards to the merged module; the scenarios and invariant checks do not change.

Ports and the slice each binds to at merge-cp:
  SyncPort       <- proto/m4-sync           (utreexo bootstrap + proof gen/verify; M4/P2-CORE)
  SettlementPort <- proto/p3-testbed        (KEYED_CRDT overlay + M2 K_fair coinbase; M1/M2/P3)
  MessagingPort  <- proto/p4-messaging      (perishable receipt, TTL-gated; P4)
  MarketPort     <- proto/p4-market         (spot hashrate delivery contract; P4)
  VenuePort      <- proto/p4-dex            (atomic two-sided settlement cross; P4)

Determinism: no wall-clock, no unseeded RNG. Every id/seed derives from sha256(i)
(the M4 convention), so the P5 suite stamp is reproducible and a changed stamp is a regression.
"""
import hashlib
from abc import ABC, abstractmethod


def h(*parts):
    """sha256 over the byte-encoding of each part (int|str|bytes). M4 convention."""
    m = hashlib.sha256()
    for p in parts:
        if isinstance(p, int):
            p = p.to_bytes(8, "big", signed=True)
        elif isinstance(p, str):
            p = p.encode()
        m.update(p)
    return m.hexdigest()


# --------------------------------------------------------------------------- #
# PORT CONTRACTS. Each is the minimal surface P5 depends on. A real adapter at
# merge-cp implements the same methods forwarding to the merged slice module.
# --------------------------------------------------------------------------- #
class SyncPort(ABC):
    """State-availability / superlight-chain sync (M4/P2-CORE). Bootstrap a node to hold the
    accumulator, then serve/verify membership proofs. NOTE: carries the cold-start anchor-trust
    fence — proofs are only load-bearing against an EXTERNALLY committed root (weak-subjectivity
    bootstrap). P5 threads that assumption through; it does not re-litigate it."""

    @abstractmethod
    def bootstrap(self, n_shares): ...          # -> committed_root (externally anchored)
    @abstractmethod
    def prove(self, share_id): ...              # -> proof
    @abstractmethod
    def verify(self, committed_root, share_id, proof): ...   # -> bool


class SettlementPort(ABC):
    """Finality-gated multichain settlement (M1/M2/P3). Feed the aux-chain event multiset;
    get back the owed ledger + bounded coinbase. Order-invariant (KEYED_CRDT), paid-once
    across anchors, value-conserving."""

    @abstractmethod
    def apply_events(self, events): ...         # -> None (accumulates owed/overlay)
    @abstractmethod
    def owed(self): ...                         # -> {miner: amount} finalized-settled
    @abstractmethod
    def coinbase(self, block_value): ...        # -> [(miner, amount)] bounded, value == block_value


class MessagingPort(ABC):
    """Perishable-receipt messaging (P4). A miner mints a TTL-bounded standing receipt; peers
    verify it only within its live epoch window."""

    @abstractmethod
    def mint(self, miner, epoch, ttl): ...      # -> receipt
    @abstractmethod
    def valid(self, receipt, now_epoch): ...    # -> bool


class MarketPort(ABC):
    """Spot hashrate market (P4). A delivery contract settles when the promised raw shares are
    delivered against the bound template; SPOT ONLY (derivatives dropped, GTM caveat)."""

    @abstractmethod
    def open_contract(self, buyer, seller, shares): ...   # -> contract_id
    @abstractmethod
    def deliver(self, contract_id, shares): ...           # -> None
    @abstractmethod
    def settle(self, contract_id): ...                    # -> Settlement(filled, paid)


class VenuePort(ABC):
    """Settlement venue / DEX (P4). Atomic two-sided cross: both legs settle or neither."""

    @abstractmethod
    def cross(self, leg_a, leg_b, head): ...    # -> MatchSettlement(atomic)


# --------------------------------------------------------------------------- #
# SLICE REGISTRY — late binding. Bind stubs now; swap for real adapters at merge-cp
# by calling register(port_name, real_adapter) BEFORE building the node. Nothing else moves.
# --------------------------------------------------------------------------- #
class SliceRegistry:
    _PORTS = ("sync", "settlement", "messaging", "market", "venue")

    def __init__(self):
        self._bind = {}

    def register(self, port_name, adapter):
        if port_name not in self._PORTS:
            raise KeyError(f"unknown port {port_name!r}; expected one of {self._PORTS}")
        self._bind[port_name] = adapter
        return self

    def get(self, port_name):
        if port_name not in self._bind:
            raise LookupError(f"port {port_name!r} not bound; register a stub or real adapter")
        return self._bind[port_name]

    def bound(self):
        return {p: type(self._bind[p]).__name__ for p in self._PORTS if p in self._bind}
