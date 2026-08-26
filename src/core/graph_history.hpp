// SPDX-License-Identifier: AGPL-3.0-or-later
//
// graph_history.hpp — coin-generic binned history database.
//
// A faithful C++ port of p2pool's p2pool/util/graph.py
// (DataViewDescription / DataView / DataStream / HistoryDatabase), used to back
// the dashboard's long-horizon graph views (last_week / last_month / last_year)
// with a bounded, fixed-point-count binned representation instead of the flat
// per-sample stat log.
//
// Semantics preserved from p2pool:
//   * bins hold {key: (total, count)}; bins[0] is the NEWEST bin;
//   * shift-bins-so-t-is-not-past-end on both add and read;
//   * keep_largest capping (with an optional squash key) for multivalue streams;
//   * get_data emits [bin_center, value, width, default] 4-tuples, value being a
//     scalar for scalar streams, a dict for multivalue streams, or null on an
//     empty gauge bin.
//
// DELIBERATE DEVIATION FROM p2pool (reviewer-signed, see PR #159): every c2pool
// stream is is_gauge=true. c2pool's StatLogEntry fields are pre-computed H/s
// rates sampled at a fixed 60s cadence, unlike p2pool's raw per-event work
// quantities. A bin therefore holds the MEAN of its samples (total/count).
// p2pool's rate semantics (total/bin_width) would rescale every long-view
// hashrate by a factor of bin_width and are intentionally NOT used for these
// streams. get_data still ports the rate branch for fidelity/tests.
//
// Output ordering deviates from p2pool too: p2pool emits newest-bin-first; this
// port emits ASCENDING in time (oldest first) to match c2pool's existing flat
// graph path, and clips leading never-filled bins server-side so the frontend
// never sees a run of nulls before real data begins.

#pragma once

#include <string>
#include <vector>
#include <map>
#include <utility>

#include <nlohmann/json.hpp>

namespace core {
namespace graph {

// A bin maps a series key to (accumulated total, sample count).
using Bin = std::map<std::string, std::pair<double, double>>;

struct DataViewDescription {
    int bin_count{0};
    double bin_width{0.0};
    DataViewDescription() = default;
    DataViewDescription(int bins, double total_width)
        : bin_count(bins), bin_width(bins > 0 ? total_width / bins : 0.0) {}
};

struct DataStreamDescription {
    // Ordered (view-name, geometry) pairs. Order is stable so the served output
    // and the persisted schema are deterministic.
    std::vector<std::pair<std::string, DataViewDescription>> dataview_descriptions;
    bool is_gauge{true};
    bool multivalues{false};
    int multivalues_keep{20};
    bool has_squash_key{false};
    std::string multivalues_squash_key;
    bool multivalue_undefined_means_0{false};
};

// keep_largest: cap a bin to at most n keys, sorted by magnitude; when a squash
// key is configured the trimmed keys are merged into it (p2pool exact). Exposed
// for unit tests (ports p2pool test_graph.py::test_keep_largest).
Bin keep_largest(const Bin& in, int n, bool has_squash,
                 const std::string& squash_key, bool is_gauge);

class DataView {
public:
    DataViewDescription desc;
    double last_bin_end{0.0};
    std::vector<Bin> bins;  // bins[0] == newest

    DataView() = default;
    DataView(const DataViewDescription& d, double lbe, std::vector<Bin> b)
        : desc(d), last_bin_end(lbe), bins(std::move(b)) {}

    // Fold one datum (t seconds, {key: value}) into the view.
    void add_datum(const DataStreamDescription& ds, double t,
                   std::map<std::string, double> value);

    // Emit ascending [center, value, width, default] 4-tuples, leading empty
    // (never-filled) bins clipped. Const: works on shifted copies.
    nlohmann::json get_data(const DataStreamDescription& ds, double t) const;

    nlohmann::json to_obj() const;
};

class DataStream {
public:
    DataStreamDescription desc;
    std::vector<std::pair<std::string, DataView>> dataviews;  // by view name

    DataStream() = default;

    void add_multi(double t, const std::map<std::string, double>& value);
    void add_scalar(double t, double value);

    DataView* view(const std::string& name);
    const DataView* view(const std::string& name) const;
};

class HistoryDatabase {
public:
    std::vector<std::pair<std::string, DataStream>> datastreams;

    // Build an empty database from the schema.
    static HistoryDatabase create(
        const std::vector<std::pair<std::string, DataStreamDescription>>& descs);

    // Build from a persisted to_obj() blob. Any view that is absent, has the
    // wrong bin geometry, or fails to parse leaves an EMPTY DataView and sets
    // needs_reseed=true so the caller can seed from the flat log instead of
    // trusting a stale/mismatched view. Never returns a null view.
    static HistoryDatabase from_obj(
        const std::vector<std::pair<std::string, DataStreamDescription>>& descs,
        const nlohmann::json& obj, bool& needs_reseed);

    nlohmann::json to_obj() const;

    DataStream* stream(const std::string& name);
    const DataStream* stream(const std::string& name) const;

    void add_scalar(const std::string& name, double t, double value);
    void add_multi(const std::string& name, double t,
                   const std::map<std::string, double>& value);
};

}  // namespace graph
}  // namespace core
