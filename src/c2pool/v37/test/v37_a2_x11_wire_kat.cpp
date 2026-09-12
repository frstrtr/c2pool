// V37 Track A2 / S-1 — carrier-wire 0x02 (real X11 share envelope) byte-KAT.
// Drives c2pool::v37n::wire_x11::selfcheck() from w3_relay_x11.hpp: the pinned
// 0x02 golden hex, the independent frame_size/offset model, lossless decode +
// byte-identical re-encode, every-strict-prefix -> REJECT_TRUNCATED, trailing
// byte, bad-version, W3-MUST carrier mis-bind, the dual-accept front door
// (routing BOTH a real 0x01 synthetic frame and a 0x02 X11 frame), and the X11
// crypto seam structurally (fail-closed when unset, set/get round-trip).
// Stdlib-only and deliberately CRYPTO-FREE: this target keeps the BYTES honest
// and states no PoW policy at all — target math, the X11 recompute and every
// verify disposition are the DASH SSOT (impl/dash/x11_share_verify.hpp).
//
// Its counterpart v37_a2_x11_real_pow_kat keeps the WORK honest: it links the
// genuine dash::crypto::hash_x11 and proves the same 0x02 envelope end-to-end
// over a REAL accepted DASH share (recomputed X11 == the node's own logged
// pow_hash, six forgeries rejected fail-closed, the frozen v0x01 golden still
// version-gated decodable). Neither target can pass while the other's concern is
// broken, and nothing S-1 relies on lives out of tree any more.
#include <c2pool/v37/w3_relay_x11.hpp>
#include <cstdio>

int main() {
    auto sc = c2pool::v37n::wire_x11::selfcheck();
    std::printf("v37_a2_x11_wire_kat: checks=%u failures=%u\n", sc.checks, sc.failures);
    if (!sc.ok()) { std::printf("%s", sc.log.c_str()); return 1; }
    return 0;
}
