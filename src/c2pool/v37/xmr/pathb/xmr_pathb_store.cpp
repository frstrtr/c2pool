// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/c2pool/v37/xmr/pathb/xmr_pathb_store.cpp
// The LevelDB binding of the Path B store (xmr_pathb_store.hpp).
// ---------------------------------------------------------------------------
#include "c2pool/v37/xmr/pathb/xmr_pathb_store.hpp"

#include <cstdint>
#include <utility>
#include <vector>

#include <core/leveldb_store.hpp>

namespace c2pool::xmr::pathb {
namespace {

core::LevelDBOptions synced_options() {
    core::LevelDBOptions o;
    o.sync_writes = true;
    o.verify_checksums = true;
    o.paranoid_checks = true;
    return o;
}

// The operations are buffered and written as one LevelDB WriteBatch at commit_sync.
class LevelDbBatch final : public PathbKvBatch {
public:
    explicit LevelDbBatch(core::LevelDBStore* db) : db_(db) {}
    void put(const std::string& k, const std::string& v) override { ops_.push_back(Op{false, k, v}); }
    void remove(const std::string& k) override { ops_.push_back(Op{true, k, {}}); }
    bool commit_sync() override {
        auto w = db_->create_batch();
        for (const Op& op : ops_) {
            if (op.remove)
                w.remove(op.key);
            else
                w.put(op.key, std::vector<std::uint8_t>(op.value.begin(), op.value.end()));
        }
        return w.commit_sync();
    }

private:
    struct Op {
        bool remove;
        std::string key;
        std::string value;
    };
    core::LevelDBStore* db_;
    std::vector<Op> ops_;
};

class LevelDbKv final : public PathbKv {
public:
    explicit LevelDbKv(const std::string& dir) : db_(dir, synced_options()) {}
    bool open() { return db_.open(); }
    std::unique_ptr<PathbKvBatch> batch() override { return std::make_unique<LevelDbBatch>(&db_); }
    std::optional<std::string> get(const std::string& k) override {
        std::vector<std::uint8_t> v;
        if (!db_.get(k, v)) return std::nullopt;
        return std::string(v.begin(), v.end());
    }
    bool for_each_prefix(const std::string& prefix,
                         const std::function<bool(const std::string&, const std::string&)>& fn) override {
        return db_.for_each_prefix(prefix, [&](const std::string& k, const std::vector<std::uint8_t>& v) {
            return fn(k, std::string(v.begin(), v.end()));
        });
    }

private:
    core::LevelDBStore db_;
};

}  // namespace

std::unique_ptr<PathbKv> open_pathb_store(const std::string& dir) {
    auto kv = std::make_unique<LevelDbKv>(dir);
    if (!kv->open()) return nullptr;
    return kv;
}

}  // namespace c2pool::xmr::pathb
