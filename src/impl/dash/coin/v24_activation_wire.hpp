// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// The v24 activation height from the S0 deployment tracking
/// (deployment_status.hpp) into the engines that fold mined blocks, as the
/// cross-check v24_activation.hpp describes. The engines fold every block as
/// its CbTx version states; the height only cross-checks, so the rules here
/// keep it from being wrong, not from stalling anything.
///
///   * Pushed only when settled: the tracking knows it (LOCKED_IN or ACTIVE
///     at the tip, or the network's buried height), it is a plausible
///     activation height for the network (v24_activation_height_refusal), and
///     the block that decided LOCKED_IN (the last block of the period before
///     the locked-in one) is kV24ActivationConfirmations deep. That is far
///     beyond any reorg a chainlocked chain allows, and still most of a
///     period before the activation block.
///   * Re-checked on every refresh: when the tracking decides that v24 is
///     inactive at the height, or active the block before it, the height is
///     withdrawn from every engine (they fall back to the blocks'
///     statements alone) and the persisted file is deleted; a different
///     settled height replaces it.
///   * Withdrawn, and the file deleted, when the tracking's own CbTx
///     cross-check latch fires (its answer was refuted by the chain).
///   * Persisted (<net>/v24_activation.v1) so a restart has it before the
///     EHF rescan; the file is parsed strictly (this format, this network,
///     nothing trailing) and its height must be plausible, else it is
///     deleted and ignored. It is only a starting point: the next refresh
///     re-checks it like any pushed height.

#include <impl/dash/coin/dash_deployments.hpp>
#include <impl/dash/coin/deployment_status.hpp>   // V24State
#include <impl/dash/coin/v24_activation.hpp>

#include <core/durable_file.hpp>   // replace: atomic write, Windows-safe rename
#include <core/log.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace dash {
namespace coin {

/// Confirmations on the block that decided LOCKED_IN before the height is
/// pushed (capped at half a period on short-window networks).
inline constexpr uint32_t kV24ActivationConfirmations = 100;

/// What the wire reads from the deployment tracking.
struct V24TrackingView
{
    /// activation_height(V24): LOCKED_IN / ACTIVE at the tip, or buried.
    std::function<std::optional<uint32_t>()> activation_height;
    /// v24_state(h) for the block at h.
    std::function<V24State(uint32_t)> state;
    /// The tracking's CbTx cross-check latch has fired.
    std::function<bool()> refuted;
    /// The header tip height.
    std::function<std::optional<uint32_t>()> tip;
};

class V24ActivationWire
{
public:
    using Sink = std::function<void(uint32_t)>;   ///< kV24HeightUnknown withdraws

    explicit V24ActivationWire(DashNetwork net, V24TrackingView view = {}, std::string persist_path = {})
        : m_net(net), m_view(std::move(view)), m_path(std::move(persist_path))
    {}

    void set_view(V24TrackingView view)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_view = std::move(view);
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

    std::optional<uint32_t> applied() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_applied;
    }

    /// Re-check the applied height against the tracking, then push a settled
    /// one (see the file comment). Returns the applied height.
    std::optional<uint32_t> refresh()
    {
        V24TrackingView v;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            v = m_view;
        }
        if (v.refuted && v.refuted()) {
            if (applied()) withdraw("the deployment tracking's CbTx cross-check latch fired");
            erase_file();
            return std::nullopt;
        }
        if (const auto a = applied(); a && v.state) {
            const V24State at = v.state(*a);
            const V24State before = *a > 0 ? v.state(*a - 1) : V24State::INACTIVE;
            if (at == V24State::INACTIVE || before == V24State::ACTIVE) {
                withdraw(std::string("the deployment tracking decides v24 is ")
                         + (at == V24State::INACTIVE ? "inactive at h=" + std::to_string(*a)
                                                     : "already active at h=" + std::to_string(*a - 1)));
                erase_file();
            }
        }
        const std::optional<uint32_t> h = v.activation_height ? v.activation_height() : std::nullopt;
        if (h) {
            if (const auto why = v24_activation_height_refusal(m_net, *h)) {
                if (m_logged_implausible != *h) {
                    m_logged_implausible = *h;
                    LOG_WARNING << "[DASH-V24] the deployment tracking's activation height " << *h
                                << " is not used: " << *why;
                }
            } else if (settled(*h, v)) {
                apply(*h, "deployment tracking");
            }
        }
        return applied();
    }

    /// Restore the persisted height (this network only, strict format,
    /// plausible) unless a height is already applied. An unusable file is
    /// deleted.
    bool load()
    {
        if (m_path.empty() || applied()) return false;
        std::ifstream in(m_path);
        if (!in) return false;
        std::stringstream ss;
        ss << in.rdbuf();
        in.close();
        const auto h = parse(m_net, ss.str());
        if (!h) {
            LOG_WARNING << "[DASH-V24] deleting " << m_path
                        << ": not a plausible v24 activation height for this network";
            erase_file();
            return false;
        }
        apply(*h, "persisted");
        return true;
    }

    static std::string serialize(DashNetwork net, uint32_t height)
    {
        return std::string(kMagic) + " " + std::to_string(static_cast<int>(net)) + " " + std::to_string(height)
             + "\n";
    }
    /// Exactly "<magic> <network> <height>" and an optional line end; the
    /// height must be a plausible activation height for `net`.
    static std::optional<uint32_t> parse(DashNetwork net, const std::string& text)
    {
        std::string body = text;
        while (!body.empty() && (body.back() == '\n' || body.back() == '\r')) body.pop_back();
        std::vector<std::string> tok;
        size_t i = 0;
        while (i <= body.size()) {
            const size_t j = body.find(' ', i);
            tok.push_back(body.substr(i, j == std::string::npos ? std::string::npos : j - i));
            if (j == std::string::npos) break;
            i = j + 1;
        }
        if (tok.size() != 3 || tok[0] != kMagic) return std::nullopt;
        auto number = [](const std::string& t, uint64_t max) -> std::optional<uint64_t> {
            if (t.empty() || t.size() > 10 || (t.size() > 1 && t[0] == '0')) return std::nullopt;
            uint64_t v = 0;
            for (char c : t) {
                if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
                v = v * 10 + static_cast<uint64_t>(c - '0');
            }
            if (v > max) return std::nullopt;
            return v;
        };
        const auto n = number(tok[1], 255);
        const auto h = number(tok[2], std::numeric_limits<uint32_t>::max() - 1);
        if (!n || !h || *n != static_cast<uint64_t>(static_cast<int>(net))) return std::nullopt;
        if (v24_activation_height_refusal(net, static_cast<uint32_t>(*h))) return std::nullopt;
        return static_cast<uint32_t>(*h);
    }

private:
    static constexpr const char* kMagic = "c2pool-dash-v24-activation/1";

    bool settled(uint32_t h, const V24TrackingView& v) const
    {
        const auto& p = dash_deployment_params(m_net);
        if (p.v24_buried_height && *p.v24_buried_height == h) return true;
        if (!v.tip) return false;
        const auto tip = v.tip();
        if (!tip) return false;
        const int64_t period = vb_period(p, p.dep(DashDeployment::V24));
        const int64_t conf = std::min<int64_t>(kV24ActivationConfirmations, std::max<int64_t>(1, period / 2));
        const int64_t deciding = static_cast<int64_t>(h) - period - 1;   // last block before LOCKED_IN
        return static_cast<int64_t>(*tip) >= deciding + conf;
    }

    void apply(uint32_t h, const char* source)
    {
        std::vector<Sink> sinks;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (m_applied == h) return;
            m_applied = h;
            sinks = m_sinks;
        }
        LOG_INFO << "[DASH-V24] activation height " << h << " (" << source << ") applied to " << sinks.size()
                 << " engine(s)";
        for (auto& s : sinks)
            if (s) s(h);
        save(h);
    }
    void withdraw(const std::string& why)
    {
        std::vector<Sink> sinks;
        std::optional<uint32_t> was;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            was = m_applied;
            m_applied.reset();
            sinks = m_sinks;
        }
        if (!was) return;
        LOG_WARNING << "[DASH-V24] activation height " << *was << " WITHDRAWN: " << why
                    << " (the folds follow each block's CbTx version alone)";
        for (auto& s : sinks)
            if (s) s(kV24HeightUnknown);
    }
    void save(uint32_t h)
    {
        if (m_path.empty()) return;
        if (!core::durable_file::replace(m_path, serialize(m_net, h)))
            LOG_WARNING << "[DASH-V24] could not persist " << m_path;
    }
    void erase_file()
    {
        if (m_path.empty()) return;
        std::error_code ec;
        std::filesystem::remove(m_path, ec);
    }

    DashNetwork m_net;
    V24TrackingView m_view;
    std::string m_path;
    mutable std::mutex m_mutex;
    std::vector<Sink> m_sinks;
    std::optional<uint32_t> m_applied;
    uint32_t m_logged_implausible{0};
};

} // namespace coin
} // namespace dash
