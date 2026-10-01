#pragma once
// DROPS-AUTO-ENROL: the XMR pool's enrolment mode and its HELLO tag. A leaf
// header (no relay / impl includes) shared by xmr_relay_wire.hpp (the HELLO
// refusal names the mode) and xmr_drops_wiring.hpp (the lane enrolment rule).
#include <cstdint>
#include <cstring>
#include <vector>
#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32, ::v37::sha256d

namespace c2pool::v37n::xmr::relay {

// ★ DROPS-AUTO-ENROL (operator ruling 09-27): the pool's enrolment MODE.
//   Auto = no --drops-enrol list: every payee enrols at its first share on the
//          lane prefix (the #1805 lane rule, no set filter) -- the default;
//   List = an explicit --drops-enrol list: only those payees (unchanged);
//   None = --drops-enrol none: nobody (DROPS armed, credits zero).
// The HELLO enrol-set digest encodes the mode: List = enrol_set_digest(list)
// (byte-identical to the list-only builds), Auto / None = a domain tag. So two
// nodes in different modes are refused at HELLO by name.
enum class EnrolMode : std::uint8_t { Auto = 0, List = 1, None = 2 };
inline const char* to_string(EnrolMode m) { return m == EnrolMode::Auto ? "auto" : m == EnrolMode::List ? "list" : "none"; }
inline ::v37::bytes32 enrol_mode_tag(EnrolMode m) {   // Auto / None only (List carries the set digest)
    const char* dom = m == EnrolMode::Auto ? "V37ENROLAUTO1" : "V37ENROLNONE1";
    std::vector<std::uint8_t> b(dom, dom + std::strlen(dom));
    return ::v37::sha256d(b);
}

}  // namespace c2pool::v37n::xmr::relay
