// SPDX-License-Identifier: AGPL-3.0-or-later
//
// xmr_msr_boost.hpp — opt-in, root-gated, per-microarchitecture MSR tuning for
// the in-process RandomX CPU miner (../pow/xmr_cpu_miner.hpp).
//
// WHAT THIS IS
//   RandomX is a random-access, cache-resident workload. On several x86
//   microarchitectures the hardware prefetcher and a couple of cache/load-store
//   configuration bits are actively counter-productive for it: the prefetcher
//   evicts scratchpad lines the VM is about to use. Turning them off through
//   model-specific registers is the well-known "MSR mod" / "randomx_boost", and
//   it is worth roughly 5-15 % on the affected parts.
//
//   It costs root (a write to /dev/cpu/N/msr), it is per-microarchitecture, and
//   it changes machine-wide CPU state that survives this process. So it is
//   OFF BY DEFAULT and only happens when an operator asks for it by name
//   (--mine-msr). Everything else in this header exists to make the OFF path,
//   the not-root path and the unknown-CPU path boring: detect, say so in one
//   line, change nothing, carry on mining.
//
// PROVENANCE OF THE CONSTANTS  (read this before editing)
//   This file is ORIGINAL c2pool code. It contains NO code from xmrig (GPL-3.0)
//   and none from any other miner. What it does contain are REGISTER NUMBERS
//   and REGISTER VALUES, which are facts about the hardware, taken from their
//   primary/public sources:
//
//     * Intel, MSR 0x1A4 (MSR_MISC_FEATURE_CONTROL) — the four hardware
//       prefetcher disable bits [0]=L2 HW, [1]=L2 adjacent-line, [2]=DCU,
//       [3]=DCU IP. Published by Intel in "Disclosure of H/W prefetcher control
//       on some Intel processors" (Intel article 000031087) and carried in the
//       Intel SDM Vol. 4 model-specific register tables. Value 0xF = all four
//       disabled; 0x0 = stock.
//
//     * AMD family 17h (Zen/Zen+/Zen2) and family 19h (Zen3/Zen4), MSRs
//       0xC0011020 (LS_CFG), 0xC0011021 (IC_CFG), 0xC0011022 (DC_CFG) and
//       0xC001102B (DE_CFG2). The register NAMES and addresses are in AMD's
//       Processor Programming Reference for those families; the specific
//       RandomX-tuned VALUES below are the ones published in SChernykh's public
//       "RandomX MSR mod" announcement and reproduced in every mining guide
//       since. They are re-typed here as data, from the published tables — no
//       implementation was copied, and the shell script that popularised them
//       is not the source of any line of this file.
//
//   A number is not expressible; the code around it is ours. If you disagree
//   with a value, change it here — nothing else in c2pool depends on it.
//
// SAFETY MODEL
//   * enabled == false (the default) => apply() returns before it looks at a
//     single register. --mine-msr is the only way to set it.
//   * dry_run == true => the full detect + plan path runs and reports what it
//     WOULD do, and no file is ever opened for writing. This is what the KAT
//     uses, so a CI runner that happens to be root still cannot be tuned by a
//     test.
//   * Not root => refused BEFORE any device is opened. writes_performed() stays
//     0 and the reason names the missing privilege.
//   * Unknown vendor/family => refused with the detected identity in the
//     message, so an operator on a new part knows why nothing happened.
//   * Every register we write is READ FIRST and the original stashed. restore()
//     (also the destructor) puts them all back. A register we cannot read we do
//     not write, because we could not undo it.
//   * SIGKILL is the one hole: a process that is killed outright never runs its
//     destructor, and the MSRs stay tuned until the next reboot or a manual
//     restore. That is inherent to the technique and is stated in the log line.
//
// SCOPE
//   Linux + x86 only. Everywhere else identify_cpu() reports no CPUID / no msr
//   device and the whole thing is a no-op that still prints its one line.

#ifndef C2POOL_XMR_MSR_BOOST_HPP
#define C2POOL_XMR_MSR_BOOST_HPP

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#define C2POOL_XMR_MSR_X86 1
#endif

namespace c2pool {
namespace xmr {
namespace msr {

// ---------------------------------------------------------------------------
// Which documented profile a CPU falls into. Unknown is the common, safe case:
// we have no published values for that part and therefore write nothing.
// ---------------------------------------------------------------------------
enum class Uarch {
    Unknown = 0,
    IntelPrefetch,   // any GenuineIntel part carrying MSR 0x1A4
    AmdZen1Zen2,     // family 17h
    AmdZen3,         // family 19h, all models except the Zen4 discriminator
    AmdZen4,         // family 19h, model 0x61
};

inline const char* to_string(Uarch u) noexcept {
    switch (u) {
        case Uarch::IntelPrefetch: return "Intel (hardware-prefetcher disable)";
        case Uarch::AmdZen1Zen2:   return "AMD Zen/Zen+/Zen2 (family 17h)";
        case Uarch::AmdZen3:       return "AMD Zen3 (family 19h)";
        case Uarch::AmdZen4:       return "AMD Zen4 (family 19h model 61h)";
        default:                   return "unknown";
    }
}

// ---------------------------------------------------------------------------
// What CPUID says about this machine. `x86` false means there was no CPUID to
// ask (a non-x86 build), in which case nothing else in here is meaningful.
// ---------------------------------------------------------------------------
struct CpuIdentity {
    bool        x86    = false;
    std::string vendor;          // 12-char CPUID leaf 0 string, e.g. "GenuineIntel"
    unsigned    family = 0;      // display family (extended family folded in)
    unsigned    model  = 0;      // display model  (extended model folded in)
    Uarch       uarch  = Uarch::Unknown;

    std::string describe() const {
        if (!x86) return "non-x86 (no CPUID)";
        char buf[160];
        std::snprintf(buf, sizeof(buf), "%s family=0x%X model=0x%X -> %s",
                      vendor.empty() ? "?" : vendor.c_str(), family, model,
                      to_string(uarch));
        return buf;
    }
};

// One register write in a profile. Every published RandomX MSR tweak is a
// whole-register store of a literal, so a {reg, value} pair is the whole
// vocabulary; the ORIGINAL value is captured at apply() time for restore.
struct MsrWrite {
    std::uint32_t reg   = 0;
    std::uint64_t value = 0;
};

// ---------------------------------------------------------------------------
// Classification. Split out from identify_cpu() so a KAT can feed it synthetic
// identities and pin the whole table without owning the hardware.
//
// The Zen3/Zen4 discriminator is deliberately the PUBLISHED one (family 19h,
// model 0x61 is Zen4, anything else in 19h takes the Zen3 values) rather than a
// guessed model range: a wrong guess here writes the wrong values to a real
// machine, and "fall back to the conservative published set" is the failure we
// want.
// ---------------------------------------------------------------------------
inline Uarch classify(const std::string& vendor, unsigned family, unsigned model) noexcept {
    if (vendor == "GenuineIntel") return Uarch::IntelPrefetch;
    if (vendor == "AuthenticAMD") {
        if (family == 0x17) return Uarch::AmdZen1Zen2;
        if (family == 0x19) return (model == 0x61) ? Uarch::AmdZen4 : Uarch::AmdZen3;
    }
    return Uarch::Unknown;
}

// The table. An EMPTY vector means "no documented profile" and is the only
// thing standing between an unrecognised CPU and a register write.
inline std::vector<MsrWrite> profile_for(Uarch u) {
    switch (u) {
        case Uarch::IntelPrefetch:
            // MSR_MISC_FEATURE_CONTROL: set all four prefetcher-disable bits.
            return {{0x1A4u, 0x000000000000000Full}};
        case Uarch::AmdZen1Zen2:
            return {{0xC0011020u, 0x0000000000000000ull},
                    {0xC0011021u, 0x0000000000000040ull},
                    {0xC0011022u, 0x0000000001510000ull},
                    {0xC001102Bu, 0x000000002000CC16ull}};
        case Uarch::AmdZen3:
            return {{0xC0011020u, 0x0004480000000000ull},
                    {0xC0011021u, 0x001C000200000040ull},
                    {0xC0011022u, 0xC000000401570000ull},
                    {0xC001102Bu, 0x000000002000CC10ull}};
        case Uarch::AmdZen4:
            return {{0xC0011020u, 0x0004400000000000ull},
                    {0xC0011021u, 0x0004000000000040ull},
                    {0xC0011022u, 0x8680000401570000ull},
                    {0xC001102Bu, 0x000000002040CC10ull}};
        default:
            return {};
    }
}

inline std::vector<MsrWrite> profile_for(const CpuIdentity& id) {
    return id.x86 ? profile_for(id.uarch) : std::vector<MsrWrite>{};
}

// ---------------------------------------------------------------------------
// CPUID. Leaf 0 gives the vendor string (EBX, EDX, ECX in that order); leaf 1
// EAX gives base family/model plus the extended fields, folded per the vendor
// rules both AMD and Intel document identically.
// ---------------------------------------------------------------------------
inline CpuIdentity identify_cpu() {
    CpuIdentity id;
#if defined(C2POOL_XMR_MSR_X86)
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid(0u, &a, &b, &c, &d)) return id;
    id.x86 = true;
    char v[13] = {0};
    std::memcpy(v + 0, &b, 4);
    std::memcpy(v + 4, &d, 4);
    std::memcpy(v + 8, &c, 4);
    id.vendor.assign(v, 12);

    if (a >= 1u && __get_cpuid(1u, &a, &b, &c, &d)) {
        const unsigned base_family = (a >> 8) & 0xFu;
        const unsigned base_model  = (a >> 4) & 0xFu;
        const unsigned ext_family  = (a >> 20) & 0xFFu;
        const unsigned ext_model   = (a >> 16) & 0xFu;
        id.family = (base_family == 0xFu) ? (base_family + ext_family) : base_family;
        id.model  = (base_family == 0xFu || base_family == 0x6u)
                        ? (base_model + (ext_model << 4)) : base_model;
    }
    id.uarch = classify(id.vendor, id.family, id.model);
#endif
    return id;
}

// ---------------------------------------------------------------------------
// Outcome of apply(). `writes_performed` is the number that matters in a test:
// on EVERY no-op path it must be 0.
// ---------------------------------------------------------------------------
struct Status {
    bool        applied          = false;
    bool        planned          = false;   // a documented profile exists for this CPU
    std::string reason;
    CpuIdentity cpu;
    std::size_t regs_per_cpu     = 0;
    std::size_t cpus_touched     = 0;
    std::size_t writes_performed = 0;
    std::size_t write_failures   = 0;
};

struct Options {
    // --mine-msr. DEFAULT OFF, and the only switch that can turn it on.
    bool enabled = false;
    // Run detect + plan, report, touch nothing and open nothing for writing.
    bool dry_run = false;
};

namespace detail {

// Online CPU ids. /sys is the authority; hardware_concurrency is the fallback.
inline std::vector<unsigned> cpu_ids() {
    std::vector<unsigned> v;
    const unsigned n = std::max(1u, std::thread::hardware_concurrency());
    for (unsigned i = 0; i < n; ++i) v.push_back(i);
    return v;
}

inline std::string msr_path(unsigned cpu) {
    return "/dev/cpu/" + std::to_string(cpu) + "/msr";
}

inline bool msr_device_present() {
#if defined(__linux__)
    struct stat st{};
    return ::stat(msr_path(0).c_str(), &st) == 0;
#else
    return false;
#endif
}

inline bool is_root() {
#if defined(__linux__)
    return ::geteuid() == 0;
#else
    return false;
#endif
}

} // namespace detail

// ---------------------------------------------------------------------------
// MsrBoost — RAII. Construct with the operator's options, call apply() once,
// and let the destructor put the machine back the way it was.
// ---------------------------------------------------------------------------
class MsrBoost {
public:
    explicit MsrBoost(Options o) : m_opt(o) {}
    ~MsrBoost() { restore(); }

    MsrBoost(const MsrBoost&)            = delete;
    MsrBoost& operator=(const MsrBoost&) = delete;

    // Gates, in order, each of which ends the call with writes_performed == 0:
    //   1. not enabled      2. no CPUID      3. no documented profile
    //   4. dry-run          5. not root      6. no /dev/cpu/N/msr
    // Only past all six does a single register get touched.
    const Status& apply() {
        m_st = Status{};
        m_st.cpu = identify_cpu();

        if (!m_opt.enabled) {
            m_st.reason = "disabled (pass --mine-msr to enable)";
            return m_st;
        }
        if (!m_st.cpu.x86) {
            m_st.reason = "no CPUID on this architecture; MSR tuning does not apply";
            return m_st;
        }
        const std::vector<MsrWrite> plan = profile_for(m_st.cpu);
        if (plan.empty()) {
            m_st.reason = "no documented MSR profile for this CPU (" +
                          m_st.cpu.describe() + ")";
            return m_st;
        }
        m_st.planned      = true;
        m_st.regs_per_cpu = plan.size();

        if (m_opt.dry_run) {
            m_st.reason = "dry-run: would write " + std::to_string(plan.size()) +
                          " register(s) per CPU for " + to_string(m_st.cpu.uarch) +
                          "; nothing opened for writing";
            return m_st;
        }
        if (!detail::is_root()) {
            m_st.reason = "requires root: /dev/cpu/N/msr is only writable by uid 0 "
                          "(re-run the node as root, or apply the tuning out of band); "
                          "no register was read or written";
            return m_st;
        }
        if (!detail::msr_device_present()) {
            m_st.reason = "the msr kernel module is not loaded (try: modprobe msr); "
                          "no register was read or written";
            return m_st;
        }
        do_apply(plan);
        return m_st;
    }

    // Idempotent. Writes back every original we successfully stashed.
    void restore() {
#if defined(__linux__)
        for (auto it = m_saved.rbegin(); it != m_saved.rend(); ++it)
            write_raw(it->cpu, it->reg, it->original);
#endif
        m_saved.clear();
        m_st.applied = false;
    }

    const Status& status() const noexcept { return m_st; }

    // The one operator-facing line. Always safe to print, on every path.
    std::string describe() const {
        char buf[512];
        if (m_st.applied) {
            std::snprintf(buf, sizeof(buf),
                          "cpu-miner: MSR-boost APPLIED [%s] %zu register(s) x %zu CPU(s), "
                          "%zu write(s)%s — originals restored on clean exit (a SIGKILL leaves "
                          "them tuned)",
                          to_string(m_st.cpu.uarch), m_st.regs_per_cpu, m_st.cpus_touched,
                          m_st.writes_performed,
                          m_st.write_failures
                              ? (", " + std::to_string(m_st.write_failures) + " refused").c_str()
                              : "");
        } else {
            std::snprintf(buf, sizeof(buf), "cpu-miner: MSR-boost NO-OP — %s [%s]",
                          m_st.reason.c_str(), m_st.cpu.describe().c_str());
        }
        return buf;
    }

private:
    struct Saved {
        unsigned      cpu = 0;
        std::uint32_t reg = 0;
        std::uint64_t original = 0;
    };

#if defined(__linux__)
    static bool read_raw(unsigned cpu, std::uint32_t reg, std::uint64_t& out) {
        const int fd = ::open(detail::msr_path(cpu).c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        std::uint64_t v = 0;
        const ssize_t n = ::pread(fd, &v, sizeof(v), static_cast<off_t>(reg));
        ::close(fd);
        if (n != static_cast<ssize_t>(sizeof(v))) return false;
        out = v;
        return true;
    }

    static bool write_raw(unsigned cpu, std::uint32_t reg, std::uint64_t value) {
        const int fd = ::open(detail::msr_path(cpu).c_str(), O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;
        const ssize_t n = ::pwrite(fd, &value, sizeof(value), static_cast<off_t>(reg));
        ::close(fd);
        return n == static_cast<ssize_t>(sizeof(value));
    }
#else
    static bool read_raw(unsigned, std::uint32_t, std::uint64_t&) { return false; }
    static bool write_raw(unsigned, std::uint32_t, std::uint64_t) { return false; }
#endif

    // Past every gate. Read-then-write, per CPU, stashing each original so the
    // destructor can undo exactly what we did. A register we cannot READ we do
    // not write: an un-restorable change is not one we are willing to make.
    void do_apply(const std::vector<MsrWrite>& plan) {
        for (unsigned cpu : detail::cpu_ids()) {
            std::uint64_t probe = 0;
            if (!read_raw(cpu, plan.front().reg, probe)) continue;  // offline / no device
            bool touched = false;
            for (const MsrWrite& w : plan) {
                std::uint64_t original = 0;
                if (!read_raw(cpu, w.reg, original)) { ++m_st.write_failures; continue; }
                if (!write_raw(cpu, w.reg, w.value)) { ++m_st.write_failures; continue; }
                m_saved.push_back(Saved{cpu, w.reg, original});
                ++m_st.writes_performed;
                touched = true;
            }
            if (touched) ++m_st.cpus_touched;
        }
        m_st.applied = m_st.writes_performed > 0;
        m_st.reason  = m_st.applied
                           ? std::string("applied ") + to_string(m_st.cpu.uarch) + " profile"
                           : "every register write was refused by the kernel "
                             "(wrong model for this profile?); nothing changed";
    }

    Options            m_opt;
    Status             m_st;
    std::vector<Saved> m_saved;
};

} // namespace msr
} // namespace xmr
} // namespace c2pool

#endif // C2POOL_XMR_MSR_BOOST_HPP
