// SPDX-License-Identifier: AGPL-3.0-or-later
// src/core/sha256_init.hpp
//
// core::init_sha256(): pick the SHA-256 implementation once, as the first
// statement of a node binary's main(), before any thread starts and before
// anything hashes.
//
// btclibs compiles Bitcoin Core's x86 implementations (SSE4, SSE4.1 4-way,
// AVX2 8-way, SHA-NI) on non-MSVC x86 builds, but until SHA256AutoDetect()
// runs every hash uses the scalar Transform. This helper:
//   1. reads C2POOL_SHA256: "standard" forces the scalar implementation (the
//      kill-switch); unset, empty or "auto" auto-detects; anything else is
//      logged and auto-detects;
//   2. calls SHA256AutoDetect();
//   3. runs SHA256SelfTest() explicitly, so the check survives NDEBUG. If the
//      selected implementation fails it, the error is logged and the scalar
//      implementation is put back. The node is never aborted;
//   4. logs one line: "[init] sha256: using <implementation>".
// SHA256AutoDetect() writes plain global function pointers, hence "before any
// thread starts". The output of every implementation is byte-identical.
#ifndef C2POOL_CORE_SHA256_INIT_HPP
#define C2POOL_CORE_SHA256_INIT_HPP

#include <btclibs/crypto/sha256.h>

#include <cstdlib>
#include <iostream>
#include <ostream>
#include <string>

namespace core {

inline constexpr const char* kSha256EnvVar = "C2POOL_SHA256";

struct Sha256Init {
    std::string implementation;              // installed now (SHA256AutoDetect's name)
    std::string detected;                    // what the detection picked, before the self-test
    bool forced_standard = false;            // C2POOL_SHA256=standard
    bool self_test_failed = false;           // `detected` failed: the scalar one was put back
    bool standard_self_test_failed = false;  // the scalar implementation failed the self-test
};

// The body of init_sha256() with its inputs passed in: `env` is the value of
// C2POOL_SHA256 (nullptr when unset), `self_test` checks the implementation
// installed at the time of the call (a test passes a failing one).
inline Sha256Init init_sha256_with(const char* env, std::ostream& log,
                                   bool (*self_test)() = &SHA256SelfTest)
{
    Sha256Init r;
    const std::string mode = env ? env : "";
    r.forced_standard = (mode == "standard");
    if (!mode.empty() && !r.forced_standard && mode != "auto")
        log << "[init] sha256: ignoring " << kSha256EnvVar << "=" << mode
            << " (accepted: standard, auto)\n";

    r.detected = SHA256AutoDetect(r.forced_standard ? sha256_implementation::STANDARD
                                                    : sha256_implementation::USE_ALL);
    r.implementation = r.detected;

    bool ok = self_test();
    if (!ok && r.detected != "standard") {
        r.self_test_failed = true;
        log << "[init] ERROR sha256: self-test failed for " << r.detected
            << "; falling back to standard\n";
        r.implementation = SHA256AutoDetect(sha256_implementation::STANDARD);
        ok = self_test();
    }
    if (!ok) {
        r.standard_self_test_failed = true;
        log << "[init] ERROR sha256: self-test failed for standard; continuing with it\n";
    }

    log << "[init] sha256: using " << r.implementation;
    if (r.forced_standard)
        log << " (" << kSha256EnvVar << "=standard)";
    else if (r.self_test_failed)
        log << " (self-test fallback)";
    log << "\n";
    log.flush();
    return r;
}

// Logs to std::clog (stderr, the stream the core logger's console sink
// writes), so a binary's stdout (--version) is unchanged.
inline Sha256Init init_sha256(std::ostream& log = std::clog)
{
    return init_sha256_with(std::getenv(kSha256EnvVar), log);
}

} // namespace core

#endif // C2POOL_CORE_SHA256_INIT_HPP
