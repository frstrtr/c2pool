// SPDX-License-Identifier: AGPL-3.0-or-later
//
// xmr_msr_boost_kat.cpp — the OFF path, the NOT-ROOT path and the UNKNOWN-CPU
// path of the opt-in MSR boost (src/impl/xmr/pow/xmr_msr_boost.hpp).
//
// WHAT THIS TEST IS FOR. --mine-msr writes model-specific registers, which is
// machine-wide state that outlives the process. The only thing a CI machine can
// honestly assert about that is the NEGATIVE: that every path which is not "an
// operator, as root, asked for this by name" changes nothing at all. So that is
// what is pinned here, and the test NEVER calls a code path that could write a
// register — not even if the runner happens to be root.
//
//   M1  the table: `classify` + `profile_for` over synthetic identities, so the
//       documented per-family register sets are pinned without owning the part;
//   M2  DEFAULT OFF: a default-constructed Options has enabled == false, and
//       apply() on it stops before it looks at a register;
//   M3  live detection on THIS machine is non-fatal and self-consistent
//       (vendor is 12 chars on x86, classify(identity) == identity.uarch);
//   M4  DRY-RUN: the full detect + plan path runs, reports what it WOULD do,
//       performs zero writes and opens nothing for writing;
//   M5  NOT ROOT: with a real (non-dry-run) apply, an unprivileged process is
//       refused with a reason that names the privilege, and writes_performed
//       stays 0. If this test IS root it SKIPS M5 loudly rather than writing;
//   M6  restore()/destructor are idempotent no-ops after any of the above, and
//       describe() is printable on every path.
//
// No RandomX, no dataset, no threads: this is the one XMR test that is cheap
// enough to build on the sanitizer leg as well, and it is registered there.

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#if defined(__linux__)
#include <unistd.h>
#endif

#include "xmr_msr_boost.hpp"

namespace msr = c2pool::xmr::msr;

static int g_fail = 0;
static void check(bool ok, const char* name, const std::string& detail = {}) {
    std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
                detail.empty() ? "" : " — ", detail.c_str());
    if (!ok) ++g_fail;
}

static bool has_reg(const std::vector<msr::MsrWrite>& p, std::uint32_t reg,
                    std::uint64_t value) {
    for (const auto& w : p)
        if (w.reg == reg && w.value == value) return true;
    return false;
}

int main() {
    std::printf("== xmr_msr_boost_kat: the opt-in MSR boost, proven by its no-ops ==\n");

    // ---- M1: the documented table ------------------------------------------
    {
        check(msr::classify("GenuineIntel", 0x6, 0xB7) == msr::Uarch::IntelPrefetch,
              "M1.a GenuineIntel -> IntelPrefetch");
        check(msr::classify("AuthenticAMD", 0x17, 0x71) == msr::Uarch::AmdZen1Zen2,
              "M1.b AMD family 17h -> Zen1/Zen2");
        check(msr::classify("AuthenticAMD", 0x19, 0x21) == msr::Uarch::AmdZen3,
              "M1.c AMD family 19h model 21h -> Zen3");
        check(msr::classify("AuthenticAMD", 0x19, 0x61) == msr::Uarch::AmdZen4,
              "M1.d AMD family 19h model 61h -> Zen4");
        check(msr::classify("AuthenticAMD", 0x15, 0x02) == msr::Uarch::Unknown,
              "M1.e pre-Zen AMD -> Unknown (no profile)");
        check(msr::classify("SomeOtherVendr", 0x6, 0x1) == msr::Uarch::Unknown,
              "M1.f unknown vendor -> Unknown (no profile)");

        // Intel: exactly one register, MSR_MISC_FEATURE_CONTROL, all four
        // hardware-prefetcher disable bits set (Intel article 000031087).
        const auto intel = msr::profile_for(msr::Uarch::IntelPrefetch);
        check(intel.size() == 1 && has_reg(intel, 0x1A4u, 0xFull),
              "M1.g Intel profile = {0x1A4 := 0xF}",
              "n=" + std::to_string(intel.size()));

        // AMD: the four LS_CFG / IC_CFG / DC_CFG / DE_CFG2 registers, per family.
        const auto z12 = msr::profile_for(msr::Uarch::AmdZen1Zen2);
        check(z12.size() == 4 && has_reg(z12, 0xC0011020u, 0x0ull) &&
                  has_reg(z12, 0xC0011021u, 0x40ull) &&
                  has_reg(z12, 0xC0011022u, 0x1510000ull) &&
                  has_reg(z12, 0xC001102Bu, 0x2000CC16ull),
              "M1.h Zen1/Zen2 profile pins the four published values");

        const auto z3 = msr::profile_for(msr::Uarch::AmdZen3);
        check(z3.size() == 4 && has_reg(z3, 0xC0011020u, 0x0004480000000000ull) &&
                  has_reg(z3, 0xC0011021u, 0x001C000200000040ull) &&
                  has_reg(z3, 0xC0011022u, 0xC000000401570000ull) &&
                  has_reg(z3, 0xC001102Bu, 0x2000CC10ull),
              "M1.i Zen3 profile pins the four published values");

        const auto z4 = msr::profile_for(msr::Uarch::AmdZen4);
        check(z4.size() == 4 && has_reg(z4, 0xC0011020u, 0x0004400000000000ull) &&
                  has_reg(z4, 0xC0011021u, 0x0004000000000040ull) &&
                  has_reg(z4, 0xC0011022u, 0x8680000401570000ull) &&
                  has_reg(z4, 0xC001102Bu, 0x2040CC10ull),
              "M1.j Zen4 profile pins the four published values");

        check(msr::profile_for(msr::Uarch::Unknown).empty(),
              "M1.k Unknown uarch has an EMPTY profile (nothing to write)");

        // The overload that takes an identity must refuse a non-x86 one even if
        // somebody hands it a populated uarch.
        msr::CpuIdentity forged;
        forged.x86   = false;
        forged.uarch = msr::Uarch::IntelPrefetch;
        check(msr::profile_for(forged).empty(),
              "M1.l a non-x86 identity yields an EMPTY profile");
    }

    // ---- M2: default OFF ----------------------------------------------------
    {
        const msr::Options def;
        check(def.enabled == false, "M2.a Options::enabled defaults to false");
        check(def.dry_run == false, "M2.b Options::dry_run defaults to false");

        msr::MsrBoost off{msr::Options{}};
        const msr::Status& s = off.apply();
        check(!s.applied, "M2.c default apply() does not apply");
        check(s.writes_performed == 0, "M2.d default apply() performs ZERO writes",
              "writes=" + std::to_string(s.writes_performed));
        check(!s.planned, "M2.e default apply() does not even build a plan");
        check(s.reason.find("--mine-msr") != std::string::npos,
              "M2.f the reason names the flag that would enable it", s.reason);
        std::printf("       %s\n", off.describe().c_str());
    }

    // ---- M3: live detection on this machine ---------------------------------
    msr::CpuIdentity live = msr::identify_cpu();
    {
        std::printf("       detected: %s\n", live.describe().c_str());
#if defined(__x86_64__) || defined(__i386__)
        check(live.x86, "M3.a CPUID answered on an x86 build");
        check(live.vendor.size() == 12,
              "M3.b vendor string is 12 characters", "'" + live.vendor + "'");
        check(msr::classify(live.vendor, live.family, live.model) == live.uarch,
              "M3.c identify_cpu() agrees with classify() on the same fields");
#else
        check(!live.x86, "M3.a non-x86 build reports no CPUID");
        check(msr::profile_for(live).empty(), "M3.b non-x86 has no profile");
#endif
        check(!live.describe().empty(), "M3.d describe() is printable");
    }

    // ---- M4: dry run --------------------------------------------------------
    {
        msr::Options o;
        o.enabled = true;
        o.dry_run = true;
        msr::MsrBoost dry{o};
        const msr::Status& s = dry.apply();
        check(!s.applied, "M4.a dry run never reports applied");
        check(s.writes_performed == 0, "M4.b dry run performs ZERO writes",
              "writes=" + std::to_string(s.writes_performed));
        check(s.cpus_touched == 0, "M4.c dry run touches ZERO cpus");
        const bool have_profile = !msr::profile_for(live).empty();
        check(s.planned == have_profile,
              "M4.d dry run plans exactly when this CPU has a documented profile",
              have_profile ? "profile present" : "no profile for this CPU");
        if (have_profile)
            check(s.reason.find("dry-run") != std::string::npos,
                  "M4.e the reason says it was a dry run", s.reason);
        else
            check(s.reason.find("no documented MSR profile") != std::string::npos ||
                      s.reason.find("no CPUID") != std::string::npos,
                  "M4.e the reason says why there was nothing to plan", s.reason);
        std::printf("       %s\n", dry.describe().c_str());
    }

    // ---- M5: not root -------------------------------------------------------
    {
#if defined(__linux__)
        const bool root = (::geteuid() == 0);
#else
        const bool root = false;
#endif
        if (root) {
            // Deliberately do NOT exercise the live path. A test that tunes the
            // machine it runs on is not a test, and CI containers do run as root.
            std::printf("  [SKIP] M5 live no-root refusal — this process IS root; "
                        "the KAT will not write MSRs under any circumstances\n");
            check(true, "M5.a skipped safely as root (no register touched)");
        } else {
            msr::Options o;
            o.enabled = true;
            o.dry_run = false;      // the real path, refused by the euid gate
            msr::MsrBoost live_try{o};
            const msr::Status& s = live_try.apply();
            check(!s.applied, "M5.a unprivileged apply() does not apply");
            check(s.writes_performed == 0,
                  "M5.b unprivileged apply() performs ZERO writes",
                  "writes=" + std::to_string(s.writes_performed));
            check(s.cpus_touched == 0, "M5.c unprivileged apply() touches ZERO cpus");
            const bool have_profile = !msr::profile_for(live).empty();
            if (have_profile)
                check(s.reason.find("root") != std::string::npos,
                      "M5.d the refusal names the missing privilege", s.reason);
            else
                check(s.reason.find("no documented MSR profile") != std::string::npos ||
                          s.reason.find("no CPUID") != std::string::npos,
                      "M5.d refused earlier, for want of a profile", s.reason);
            std::printf("       %s\n", live_try.describe().c_str());
        }
#if defined(__linux__)
        // Whatever happened above, the msr device is either absent or was never
        // opened for writing by this process. Report which, for the record.
        std::printf("       /dev/cpu/0/msr present=%s euid=%u\n",
                    msr::detail::msr_device_present() ? "yes" : "no",
                    static_cast<unsigned>(::geteuid()));
#endif
    }

    // ---- M6: restore is an idempotent no-op ---------------------------------
    {
        msr::Options o;
        o.enabled = true;
        o.dry_run = true;
        msr::MsrBoost b{o};
        b.apply();
        b.restore();
        b.restore();            // idempotent
        check(b.status().writes_performed == 0,
              "M6.a restore after a no-op apply writes nothing");
        check(!b.status().applied, "M6.b status is not 'applied' after restore");
        check(!b.describe().empty(), "M6.c describe() is printable after restore");
        // Destructor runs here and must also be a no-op.
    }

    std::printf("== xmr_msr_boost_kat: %s (%d failure%s) ==\n",
                g_fail ? "FAIL" : "PASS", g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
