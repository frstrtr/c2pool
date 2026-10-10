// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/xmr_pathb_store.hpp
// The Path B store archive (xmr_pathb_store): the node's own store in a
// LevelDB directory of its own, behind the core-free KV seam
// (impl/xmr/pathb/pathb_kv.hpp). Every batch is one synced LevelDB
// WriteBatch; reads verify checksums; a scan fails closed.
//   <data>/<network>/pathb_db/<pool_id hex>-<G hex>   (store_dir_name)
// Not linked into any running target.
// ---------------------------------------------------------------------------
#pragma once

#include <memory>
#include <string>

#include "impl/xmr/pathb/pathb_kv.hpp"

namespace c2pool::xmr::pathb {

// nullptr: the directory does not open.
std::unique_ptr<PathbKv> open_pathb_store(const std::string& dir);

}  // namespace c2pool::xmr::pathb
