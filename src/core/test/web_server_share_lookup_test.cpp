// SPDX-License-Identifier: AGPL-3.0-or-later
// /web/share/<hash> (MiningInterface::rest_web_share): the coin's share
// lookup answers; an unknown hash, or no lookup wired, is "share not found";
// a lookup that found the tracker locked is "tracker busy", which share.html
// asks again for instead of showing a held share as not found.
#include <gtest/gtest.h>

#include <string>

#include <nlohmann/json.hpp>

#include <core/web_server.hpp>

namespace {

const std::string kHash(64, 'a');

} // namespace

TEST(WebShareLookup, NoLookupIsNotFound)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::BITCOIN);
    const auto r = mi.rest_web_share(kHash);
    EXPECT_EQ(r, (nlohmann::json{{"error", "share not found"}, {"hash", kHash}}));
}

TEST(WebShareLookup, LookupDocumentIsServed)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::BITCOIN);
    mi.set_share_lookup_fn([](const std::string& h) {
        return nlohmann::json{{"hash", h}, {"parent", std::string(64, '0')}, {"type_name", "V35"}};
    });
    const auto r = mi.rest_web_share(kHash);
    EXPECT_EQ(r.value("hash", ""), kHash);
    EXPECT_EQ(r.value("type_name", ""), "V35");
    EXPECT_FALSE(r.contains("error"));
}

TEST(WebShareLookup, UnknownHashIsNotFound)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::BITCOIN);
    mi.set_share_lookup_fn([](const std::string&) {
        return nlohmann::json{{"error", "share not found"}};
    });
    EXPECT_EQ(mi.rest_web_share(kHash),
              (nlohmann::json{{"error", "share not found"}, {"hash", kHash}}));
}

TEST(WebShareLookup, BusyTrackerIsReportedAsBusy)
{
    core::MiningInterface mi(false, nullptr, c2pool::address::Blockchain::BITCOIN);
    mi.set_share_lookup_fn([](const std::string&) {
        return nlohmann::json{{"error", "tracker busy"}};
    });
    EXPECT_EQ(mi.rest_web_share(kHash),
              (nlohmann::json{{"error", "tracker busy"}, {"hash", kHash}}));
}
