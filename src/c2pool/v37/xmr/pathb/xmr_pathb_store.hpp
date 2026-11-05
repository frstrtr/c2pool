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
// WriteBatch; point reads verify checksums (scans do not; the load's anchors
// cover them); a read error is never "absent"; a scan fails closed.
//   <data>/<network>/pathb_db/<pool_id hex>-<G hex>   (store_dir_name)
// A store LevelDB cannot read (a full scan fails) is moved aside to a sibling
// <dir>.corrupt-<unix s> (nothing deleted) and an empty store opened in its
// place (move_store_aside).
// Linked into c2pool-v37-xmr.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "impl/xmr/pathb/pathb_kv.hpp"

namespace c2pool::xmr::pathb {

// nullptr: the directory does not open.
std::unique_ptr<PathbKv> open_pathb_store(const std::string& dir);

// A full scan of the store (every key). false: LevelDB could not read it (a corrupt block, an IO error).
bool store_readable(PathbKv& kv);

// The store in `dir` is closed and moved aside to the sibling `<dir>.corrupt-<unix_s>` (with -2, -3, ... when that
// name exists; nothing is deleted), and an empty store is opened in `dir`. `moved`: the sibling's path. nullptr and
// `why` when the move or the open fails.
std::unique_ptr<PathbKv> move_store_aside(std::unique_ptr<PathbKv> kv, const std::string& dir, std::uint64_t unix_s,
                                          std::string& moved, std::string& why);

}  // namespace c2pool::xmr::pathb
