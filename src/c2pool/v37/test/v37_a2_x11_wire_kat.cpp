// V37 Track A2 / S-1 — carrier-wire 0x02 (real X11 share envelope) byte-KAT.
// Drives c2pool::v37n::wire_x11::selfcheck() from w3_relay_x11.hpp: the pinned
// 0x02 golden hex, the independent frame_size/offset model, lossless decode +
// byte-identical re-encode, every-strict-prefix -> REJECT_TRUNCATED, trailing
// byte, bad-version, W3-MUST carrier mis-bind, the dual-accept front door
// (routing BOTH a real 0x01 synthetic frame and a 0x02 X11 frame), and the
// injected-hook X11 verify path incl. its FAIL-CLOSED no-hook case. Stdlib-only:
// the X11 permutation is reached through an injected sha256d stub, so the KAT
// needs no SSOT link (mirrors v37_w3_wire_freeze_kat). The daemon installs the
// real dash::crypto::hash_x11 hook at boot; the SSOT-linked end-to-end real-X11
// proof (dash::verify_x11_share + X11ReceiptAdmitter over a live mining.submit)
// lives in the out-of-tree S-1 proof harness described in the PR.
#include <c2pool/v37/w3_relay_x11.hpp>
#include <cstdio>

int main() {
    auto sc = c2pool::v37n::wire_x11::selfcheck();
    std::printf("v37_a2_x11_wire_kat: checks=%u failures=%u\n", sc.checks, sc.failures);
    if (!sc.ok()) { std::printf("%s", sc.log.c_str()); return 1; }
    return 0;
}
