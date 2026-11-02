// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Negative control for ci/check_key_free.sh (ctest
// dash_key_scan_probe_key_free_guard_negative_control, WILL_FAIL): a binary
// that links the BIP32 funding-key scan (KeyScan.cpp) and nothing else of the
// DASH key layer — no DashMessage, no signer. The guard must REJECT it. Before
// the scan & plan split the guard's token list did not see this code at all;
// this probe keeps that blind spot from coming back.

#include "../KeyScan.hpp"

int main(int argc, char** argv)
{
    // Never taken at test time; the reference is what makes the linker pull
    // KeyScan.cpp's object (and the hdkeys derivation it calls) into the binary.
    if (argc > 4) {
        const c2w::dash::FoundKey k = c2w::dash::find_key_for_address(argv[1], argv[2], argv[3], false, 0, 1, false);
        return k.compressed ? 1 : 2;
    }
    return 0;
}
