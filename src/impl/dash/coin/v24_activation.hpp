// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The Dash Core v24 activation height for the engines that switch their
/// rules at a height: the payee projection (MnStateMachine) and the
/// root-checked replay folds (DmlFoldEngine). Both fold MINED blocks, in
/// height order, and need to know for each block whether DEPLOYMENT_V24 is
/// active for it (Core DeploymentActiveAfter(pindexPrev, V24)).
///
/// Two sources, used together:
///
///   1. The S0 deployment tracking (deployment_status.hpp
///      activation_height(V24)): the EHF signal tracker plus the versionbits
///      machine over our header chain. It knows the activation height once
///      the deployment is LOCKED_IN, a full window (4,032 blocks on mainnet)
///      before the activation block, or at once for a buried height
///      (testnet 1,578,000). V24ActivationWire pushes it into every engine on
///      each ordered block and at startup, and persists it, so a restart
///      after activation restores it before the tracker has rescanned.
///      Activation is decided by the signalling of a whole window before it,
///      far beyond any reorg a chainlocked chain allows, so a pushed height
///      is never withdrawn; a different height from the tracking replaces it.
///
///   2. The block itself. Dash Core requires CbTx version 4 exactly when V24
///      (and V20) is active for the block (CheckCbTx, bad-cbtx-version), so
///      every block from V20 on states the switch. v24_block_switch() checks the
///      pushed height against it: a contradiction refuses the block before
///      any mutation (fail closed, the engines' own refusal paths). With no
///      height pushed yet (a cold restart after activation, before the
///      tracker caught up and without the persisted file), the block's
///      statement decides and the engine adopts that block's height: v24 is
///      monotone, and every earlier block it folded stated "inactive".

#include <impl/dash/coin/dash_deployments.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>

#include <core/durable_file.hpp>   // replace: atomic write, Windows-safe rename
#include <core/log.hpp>

#include <cstdint>
#include <fstream>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// "No activation height known" in the engines (never active by height).
inline constexpr uint32_t kV24HeightUnknown = std::numeric_limits<uint32_t>::max();

/// The CbTx version a block states, or nullopt when its coinbase carries no
/// parseable CbTx (before DIP-3).
template <typename Block>
std::optional<uint16_t> block_cbtx_version(const Block& block)
{
    if (block.m_txs.empty() || block.m_txs[0].type != 5) return std::nullopt;
    vendor::CCbTx cb;
    if (!vendor::parse_cbtx(block.m_txs[0].extra_payload, cb)) return std::nullopt;
    return cb.nVersion;
}

/// The v24 switch of one mined block (see the file comment).
struct V24BlockSwitch
{
    bool active{false};
    /// No height was known and the block stated "active": the engine adopts
    /// this block's height as the activation height.
    bool learned{false};
    /// The known height and the block's CbTx version disagree.
    std::optional<std::string> contradiction;
};

/// A block states the switch only once V20 is active for it (CbTx version 3
/// or 4: Core requires 4 when V24 && V20, 3 when V20 alone). An older CbTx
/// (or none) states nothing; on mainnet and testnet V24 starts long after V20.
inline V24BlockSwitch v24_block_switch(uint32_t height, uint32_t activation_height,
                                       std::optional<uint16_t> cbtx_version)
{
    V24BlockSwitch s;
    const bool states = cbtx_version && *cbtx_version >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    const bool stated = states && *cbtx_version >= vendor::CCbTx::VERSION_MERKLE_ROOT_ASSETUNLOCKS;
    if (activation_height != kV24HeightUnknown) {
        s.active = height >= activation_height;
        if (states && stated != s.active)
            s.contradiction = "Dash Core v24 switch contradiction at h=" + std::to_string(height)
                            + ": the activation height " + std::to_string(activation_height)
                            + " says " + (s.active ? "active" : "inactive") + " but the block's CbTx is version "
                            + std::to_string(*cbtx_version) + " (version 4 exactly when v24 is active)";
        return s;
    }
    s.active = stated;
    s.learned = stated;
    return s;
}

/// Pushes the S0 activation height into every engine that needs it, and
/// persists it (see the file comment). Thread-safe; the sinks are called
/// outside the lock, from the thread that calls refresh()/load()/add_sink().
class V24ActivationWire
{
public:
    using HeightFn = std::function<std::optional<uint32_t>()>;
    using Sink = std::function<void(uint32_t)>;

    explicit V24ActivationWire(DashNetwork net, HeightFn fn = {}, std::string persist_path = {})
        : m_net(net), m_fn(std::move(fn)), m_path(std::move(persist_path))
    {}

    void set_height_fn(HeightFn fn)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_fn = std::move(fn);
    }

    /// Register an engine; it receives the applied height at once, if any.
    void add_sink(Sink s)
    {
        std::optional<uint32_t> h;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_sinks.push_back(s);
            h = m_applied;
        }
        if (h && s) s(*h);
    }

    /// Ask the tracking again; push and persist a new height. Returns the
    /// applied height (unchanged when the tracking does not know).
    std::optional<uint32_t> refresh()
    {
        HeightFn fn;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            fn = m_fn;
        }
        const std::optional<uint32_t> h = fn ? fn() : std::nullopt;
        if (h) apply(*h, "deployment tracking");
        return applied();
    }

    std::optional<uint32_t> applied() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_applied;
    }

    /// Restore the persisted height (this network only) and push it.
    bool load()
    {
        if (m_path.empty()) return false;
        std::ifstream in(m_path);
        if (!in) return false;
        std::stringstream ss;
        ss << in.rdbuf();
        const auto h = parse(m_net, ss.str());
        if (!h) {
            LOG_WARNING << "[DASH-V24] ignoring " << m_path << ": not an activation height for this network";
            return false;
        }
        apply(*h, "persisted");
        return true;
    }

    static std::string serialize(DashNetwork net, uint32_t height)
    {
        return "c2pool-dash-v24-activation/1 " + std::to_string(static_cast<int>(net)) + " "
             + std::to_string(height) + "\n";
    }
    static std::optional<uint32_t> parse(DashNetwork net, const std::string& text)
    {
        std::istringstream in(text);
        std::string magic;
        int n = -1;
        long long h = -1;
        if (!(in >> magic >> n >> h)) return std::nullopt;
        if (magic != "c2pool-dash-v24-activation/1" || n != static_cast<int>(net)) return std::nullopt;
        if (h <= 0 || h >= static_cast<long long>(kV24HeightUnknown)) return std::nullopt;
        return static_cast<uint32_t>(h);
    }

private:
    void apply(uint32_t h, const char* source)
    {
        std::vector<Sink> sinks;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (m_applied == h) return;
            m_applied = h;
            sinks = m_sinks;
        }
        LOG_INFO << "[DASH-V24] activation height " << h << " (" << source << ") applied to "
                 << sinks.size() << " engine(s)";
        for (auto& s : sinks)
            if (s) s(h);
        save(h);
    }
    void save(uint32_t h)
    {
        if (m_path.empty()) return;
        if (!core::durable_file::replace(m_path, serialize(m_net, h)))
            LOG_WARNING << "[DASH-V24] could not persist " << m_path;
    }

    DashNetwork m_net;
    HeightFn m_fn;
    std::string m_path;
    mutable std::mutex m_mutex;
    std::vector<Sink> m_sinks;
    std::optional<uint32_t> m_applied;
};

} // namespace coin
} // namespace dash
