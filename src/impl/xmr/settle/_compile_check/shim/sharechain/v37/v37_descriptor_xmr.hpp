// COMPILE-CHECK SHIM ONLY -- not a deliverable. Provides exactly the symbols
// w5-coinbase uses from the descriptor-kinds leg's real
// src/sharechain/v37/v37_descriptor_xmr.hpp (+ the canon's ScriptRef/bytes32),
// self-contained so no v37_descriptor.hpp / v37_hash.hpp stub is needed.
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace v37 {

enum class ScriptKind : std::uint8_t {};   // real canon: fixed-underlying enum class

struct ScriptRef {
    ScriptKind kind{};
    std::vector<std::uint8_t> payload;
};

struct bytes32 {
    std::array<std::uint8_t, 32> b{};
    std::uint8_t*       data()       noexcept { return b.data(); }
    const std::uint8_t* data() const noexcept { return b.data(); }
    static constexpr std::size_t size() noexcept { return 32; }
};

namespace xmr {

inline constexpr ScriptKind XMR_STD = static_cast<ScriptKind>(0x10);
inline constexpr ScriptKind XMR_SUB = static_cast<ScriptKind>(0x11);
inline constexpr std::size_t   XMR_POINT_LEN   = 32;
inline constexpr std::size_t   XMR_PAYLOAD_LEN = 64;
inline constexpr std::uint32_t XMR_OUTPUT_SIZE_BYTES = 42;
inline constexpr std::uint8_t  XMR_PRECARROT_MAX_MAJOR_VERSION = 16;

inline constexpr bool xmr_precarrot_ok(std::uint8_t v) {
    return v <= XMR_PRECARROT_MAX_MAJOR_VERSION;
}
inline constexpr bool is_xmr_kind(ScriptKind k) {
    return k == XMR_STD || k == XMR_SUB;
}

} // namespace xmr
} // namespace v37
