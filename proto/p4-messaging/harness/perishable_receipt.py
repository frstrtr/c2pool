"""V37 P4 — perishable-receipt messaging: deterministic reference core.

Prototype (no consensus code) of the perishable-receipt / TTL-messaging primitive
specified in docs/c2pool-v37-ttl-messaging.md + c2pool-v37-miner-messages.md.

Design properties exercised by the golden harness (see run_p4.py):
  P4-1  Perishable / current-difficulty:   a receipt is valid ONLY against the
        verifier's current epoch target; a receipt precomputed in a cheap PAST
        epoch (backdated) is REJECTED even if its PoW cleared the old target.
  P4-2  TTL freshness:                      a receipt whose epoch is outside
        [now-TTL, now] is DEAD (expired or from the future).
  P4-3  Signed / anti-grief:                a receipt is bound to a derived
        signing_id (miner-messages §3.2, HMAC-derived key); a forged signature
        is IGNORED and nobody can mint standing against a victim's signing_id.
  P4-4  Standing is ephemeral + domain-scoped + sybil-TAXED (linear):
        splitting one identity of standing S into N sybils yields N*(S/N)=S
        total standing — no superlinear gain; standing decays out of the window.

Determinism: NO wall-clock, NO RNG. "Epoch" is an integer counter (the L0 bin
clock). Keys/targets derive from fixed seeds via sha256/HMAC-sha256. Signatures
are modelled as HMAC-SHA256(signing_privkey, msg) — a keyed binding that carries
the SAME anti-forge / anti-grief invariant under test as the spec's ECDSA leg
(the curve is out of scope for the freshness/standing invariants; the ed25519
leg is proven separately in the M4 t18 harness).
"""
import hashlib
import hmac

# ---- chain params (would be consensus params) -----------------------------
TTL = 4                    # epochs a receipt stays fresh: valid in [now-TTL, now]
TTL_WORK_UNIT = 1          # work-equiv per standing unit (abstract)
STANDING_WINDOW = 8        # epochs of standing retained (ephemeral)
DIFFICULTY_LEADING_ZERO_BITS = 8   # per-epoch target: PoW hash must have >= this many
                                   # leading zero bits AGAINST THE CURRENT epoch salt


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def leading_zero_bits(b: bytes) -> int:
    n = 0
    for byte in b:
        if byte == 0:
            n += 8
            continue
        # count leading zeros in this byte
        for k in range(7, -1, -1):
            if byte & (1 << k):
                return n
            n += 1
        break
    return n


# ---- identity: HMAC-derived signing keys (miner-messages §3.2, A-1) --------
def derive_signing_privkey(master_privkey: bytes, key_index: int) -> bytes:
    return hmac.new(master_privkey,
                    b"p2pool-msg-v1" + key_index.to_bytes(4, "little"),
                    hashlib.sha256).digest()


def signing_id(signing_privkey: bytes) -> bytes:
    # HASH160 stand-in (sha256 twice, take 20 bytes) — id is what standing is keyed on
    return _h(_h(signing_privkey))[:20]


def sign(signing_privkey: bytes, payload: bytes) -> bytes:
    return hmac.new(signing_privkey, payload, hashlib.sha256).digest()


def verify_sig(sid: bytes, signing_privkey_claimed: bytes, payload: bytes, sig: bytes) -> bool:
    # the announcing share binds signing_id -> derived pubkey; here the id must match the
    # key that produced the sig, and the sig must verify. A forged sig or a sid that does
    # not derive from the signing key both fail (anti-grief: cannot mint under a victim id).
    if signing_id(signing_privkey_claimed) != sid:
        return False
    return hmac.compare_digest(sign(signing_privkey_claimed, payload), sig)


# ---- the perishable receipt -----------------------------------------------
def epoch_salt(epoch: int) -> bytes:
    # per-epoch randomness anchor (gossiped beacon in the spec); deterministic here
    return _h(b"epoch-beacon", epoch.to_bytes(8, "little"))


def mine_receipt(master_privkey: bytes, key_index: int, epoch: int,
                 domain: bytes, message: bytes, max_nonce: int = 1 << 24):
    """Grind a nonce so the PoW clears the target FOR `epoch`. Returns a receipt dict
    or None if not found within max_nonce (params are tuned so it always finds one)."""
    sk = derive_signing_privkey(master_privkey, key_index)
    sid = signing_id(sk)
    salt = epoch_salt(epoch)
    core = sid + domain + message + epoch.to_bytes(8, "little")
    for nonce in range(max_nonce):
        pow_hash = _h(salt, core, nonce.to_bytes(8, "little"))
        if leading_zero_bits(pow_hash) >= DIFFICULTY_LEADING_ZERO_BITS:
            sig = sign(sk, core + nonce.to_bytes(8, "little"))
            return {
                "signing_id": sid, "signing_key": sk, "key_index": key_index,
                "epoch": epoch, "domain": domain, "message": message,
                "nonce": nonce, "sig": sig, "pow_hash": pow_hash,
            }
    return None


def verify_receipt(r: dict, now_epoch: int) -> tuple[bool, str]:
    """The full perishable-receipt admission check at verification time."""
    # (1) TTL freshness — perishable: epoch must be within [now-TTL, now]
    if r["epoch"] > now_epoch:
        return False, "future-epoch"
    if r["epoch"] < now_epoch - TTL:
        return False, "expired-ttl"
    # (2) current-difficulty / perishable anchor — the PoW must clear the target
    #     recomputed against THE RECEIPT'S epoch salt, and that epoch must be fresh (1).
    #     A receipt precomputed in a stale/cheap past epoch is killed by (1), NOT reusable.
    core = r["signing_id"] + r["domain"] + r["message"] + r["epoch"].to_bytes(8, "little")
    pow_hash = _h(epoch_salt(r["epoch"]), core, r["nonce"].to_bytes(8, "little"))
    if pow_hash != r["pow_hash"]:
        return False, "pow-mismatch"
    if leading_zero_bits(pow_hash) < DIFFICULTY_LEADING_ZERO_BITS:
        return False, "insufficient-work"
    # (3) signed / anti-grief
    if not verify_sig(r["signing_id"], r["signing_key"], core + r["nonce"].to_bytes(8, "little"), r["sig"]):
        return False, "bad-sig"
    return True, "ok"


# ---- ephemeral, domain-scoped standing accumulator ------------------------
class Standing:
    """Standing = count of fresh, valid receipts per (signing_id, domain), windowed.
    Ephemeral: receipts outside the STANDING_WINDOW are evicted (garbage-collected)."""

    def __init__(self):
        self._events = []  # (epoch, signing_id, domain)

    def admit(self, r: dict, now_epoch: int) -> bool:
        ok, _ = verify_receipt(r, now_epoch)
        if not ok:
            return False
        self._events.append((r["epoch"], r["signing_id"], r["domain"]))
        return True

    def standing(self, sid: bytes, domain: bytes, now_epoch: int) -> int:
        return sum(1 for (e, s, d) in self._events
                   if s == sid and d == domain and e > now_epoch - STANDING_WINDOW)
