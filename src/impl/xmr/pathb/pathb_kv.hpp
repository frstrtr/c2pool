// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_kv.hpp
// Path B, slice S4w-a: the key-value seam of the node's own store. A batch
// ends in commit_sync only (one synced write, applied whole or not at all);
// a prefix scan returns false on an iterator or IO error, never "empty".
// The binding to a database is outside this tree (xmr_pathb_store).
//
// Header-only. Not included by any running component; included by its KATs only.
// ---------------------------------------------------------------------------
#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace c2pool::xmr::pathb {

class PathbKvBatch {
public:
    virtual ~PathbKvBatch() = default;
    virtual void put(const std::string& k, const std::string& v) = 0;
    virtual void remove(const std::string& k) = 0;
    virtual bool commit_sync() = 0;  // false: not written (torn / IO error)
};

class PathbKv {
public:
    virtual ~PathbKv() = default;
    virtual std::unique_ptr<PathbKvBatch> batch() = 0;
    virtual std::optional<std::string> get(const std::string& k) = 0;
    virtual bool for_each_prefix(const std::string& prefix,
                                 const std::function<bool(const std::string& k, const std::string& v)>& fn) = 0;
};

}  // namespace c2pool::xmr::pathb
