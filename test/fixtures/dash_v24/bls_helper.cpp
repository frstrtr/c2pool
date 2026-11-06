// SPDX-License-Identifier: AGPL-3.0-or-later
//
// BLS helper for gen_s2_vectors.py: the real operator keys and signatures of
// the synthetic S2 vectors, from fixed secrets, with dashbls (the library
// dashd wraps in src/bls/bls.h). Not part of the build. Build it by hand
// against a dashbls install (scripts/build_dashbls.sh), e.g.
//
//   g++ -std=c++20 -O1 -I"$DASHBLS_ROOT/include" bls_helper.cpp \
//       "$DASHBLS_ROOT/lib/libdashbls.a" -lgmp -o bls_helper
//
// Commands (hex in, hex out; <legacy> is 0 for the basic scheme, 1 for legacy):
//   pub  <secret32>  <legacy>            -> the G1 public key, 48 bytes
//   sign <secret32>  <hash32> <legacy>   -> CBLSSecretKey::Sign(hash): the
//                                           scheme's Sign over the 32 hash
//                                           bytes as given, 96 bytes
//   g1valid <bytes48> <legacy>           -> 1/0: CBLSWrapper::SetBytes valid
//                                           AND CheckMalleable (Core's Get())
//   g2decodes <bytes96> <legacy>         -> 1/0: CBLSSignature::Unserialize
//                                           does not throw
// The secret convention is Core's evo_simplifiedmns_tests: {i, 0, ..., 0}.

#include <dashbls/bls.hpp>
#include <dashbls/elements.hpp>
#include <dashbls/schemes.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> unhex(const char* s)
{
    std::vector<uint8_t> out;
    const size_t n = std::strlen(s);
    if (n % 2) throw std::runtime_error("odd hex");
    for (size_t i = 0; i < n; i += 2) {
        unsigned v = 0;
        if (std::sscanf(s + i, "%2x", &v) != 1) throw std::runtime_error("bad hex");
        out.push_back(static_cast<uint8_t>(v));
    }
    return out;
}

void put(const std::vector<uint8_t>& b)
{
    for (uint8_t c : b) std::printf("%02x", c);
    std::printf("\n");
}

template <typename E>
bool set_bytes_canonical(const std::vector<uint8_t>& b, bool legacy)
{
    if (std::all_of(b.begin(), b.end(), [](uint8_t c) { return c == 0; })) return false;
    try {
        const E e = E::FromBytes(bls::Bytes(b.data(), b.size()), legacy);
        if (e == E()) return false;
        return e.Serialize(legacy) == b;
    } catch (...) {
        return false;
    }
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc < 2) return 2;
        const std::string cmd = argv[1];
        if (cmd == "pub" && argc == 4) {
            const auto sk = bls::PrivateKey::FromBytes(bls::Bytes(unhex(argv[2])));
            put(sk.GetG1Element().Serialize(std::string(argv[3]) == "1"));
            return 0;
        }
        if (cmd == "sign" && argc == 5) {
            const auto sk = bls::PrivateKey::FromBytes(bls::Bytes(unhex(argv[2])));
            const auto h = unhex(argv[3]);
            if (h.size() != 32) return 2;
            const bool legacy = std::string(argv[4]) == "1";
            bls::G2Element sig;
            if (legacy) sig = bls::LegacySchemeMPL().Sign(sk, bls::Bytes(h));
            else        sig = bls::BasicSchemeMPL().Sign(sk, bls::Bytes(h));
            put(sig.Serialize(legacy));
            return 0;
        }
        if (cmd == "g1valid" && argc == 4) {
            const auto b = unhex(argv[2]);
            if (b.size() != 48) return 2;
            std::printf("%d\n", set_bytes_canonical<bls::G1Element>(b, std::string(argv[3]) == "1") ? 1 : 0);
            return 0;
        }
        if (cmd == "g2decodes" && argc == 4) {
            const auto b = unhex(argv[2]);
            if (b.size() != 96) return 2;
            const bool legacy = std::string(argv[3]) == "1";
            const bool zero = std::all_of(b.begin(), b.end(), [](uint8_t c) { return c == 0; });
            const bool ok = zero || set_bytes_canonical<bls::G2Element>(b, legacy)
                                 || set_bytes_canonical<bls::G2Element>(b, !legacy);
            std::printf("%d\n", ok ? 1 : 0);
            return 0;
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "bls_helper: %s\n", e.what());
        return 1;
    }
    return 2;
}
