// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_node.hpp
//
// XmrNode: the descriptor backends of the XMR node. bring_up() installs the
// ed25519 point-check backend (which makes the P-1 XMR descriptor validator
// live) and refuses to run without one (fail-closed). The node's payout state
// is the Path B node's (c2pool/v37/xmr/pathb/).
// ===========================================================================
#pragma once

#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sharechain/v37/v37_descriptor_xmr.hpp>     // point_check_backend, xmr_ref_valid

#include "xmr_node_config.hpp"

namespace c2pool::v37n::xmr {

class XmrNode {
public:
    // `point_check` optionally injects the ed25519 backend explicitly (production links the ref10 registrar, which
    // also auto-installs at static init; a light test with no crypto link passes a test predicate so the
    // fail-closed guard can be exercised).
    explicit XmrNode(XmrNodeConfig cfg, ::v37::xmr::xmr_point_check_fn point_check = nullptr)
        : m_cfg(std::move(cfg)), m_injected_point_check(point_check) {}

    XmrNode(const XmrNode&) = delete;
    XmrNode& operator=(const XmrNode&) = delete;

    // Throws std::runtime_error with no descriptor backend (fail-closed).
    void bring_up() {
        log("bring_up: begin (network=" + std::string(to_string(m_cfg.network)) + ")");
        install_descriptor_backends();
        log("backends: point-check installed; XMR descriptors validate");
        m_up = true;
        log("bring_up: complete");
    }
    bool up() const noexcept { return m_up; }
    const XmrNodeConfig& config() const noexcept { return m_cfg; }
    const std::vector<std::string>& construction_log() const { return m_log; }

private:
    // Install the ed25519 point-check backend (which is ALSO what makes the P-1
    // XMR descriptor validator live: xmr_ref_valid() fails closed with no
    // backend). Under V37_XMR_HAVE_MONERO_CRYPTO the ref10 registrar TU has
    // already auto-installed at static init; we (a) honour an explicit injection,
    // (b) ASSERT a backend is live, and (c) refuse to run otherwise.
    void install_descriptor_backends() {
        if (m_injected_point_check)
            ::v37::xmr::set_point_check_backend(m_injected_point_check);
        if (::v37::xmr::point_check_backend() == nullptr)
            throw std::runtime_error(
                "XmrNode: no ed25519 point-check backend installed -- XMR descriptors "
                "would fail closed. Link v37_descriptor_xmr_point_check_ref10.cpp "
                "(V37_XMR_HAVE_MONERO_CRYPTO) or inject a backend.");
    }

    void log(const std::string& s) { m_log.push_back(s); }

    XmrNodeConfig                  m_cfg;
    ::v37::xmr::xmr_point_check_fn m_injected_point_check;
    std::vector<std::string>       m_log;
    bool                           m_up = false;
};

} // namespace c2pool::v37n::xmr
