// SPDX-License-Identifier: AGPL-3.0-or-later
//
// graph_history.cpp — implementation of the p2pool graph.py binning port.
// See graph_history.hpp for the design notes and the deliberate deviations.

#include <core/graph_history.hpp>

#include <algorithm>
#include <cmath>
#include <limits>

namespace core {
namespace graph {

namespace {

// _shift(x, shift, {}) restricted to shift >= 0 (the only case
// _shift_bins_so_t_is_not_past_end ever produces): prepend `shift` empty bins
// at the newest end (index 0) and drop the same number of the oldest bins.
std::vector<Bin> shift_bins(const std::vector<Bin>& x, long shift) {
    long n = static_cast<long>(x.size());
    if (shift <= 0) return x;
    if (shift >= n) return std::vector<Bin>(static_cast<size_t>(n));  // all empty
    std::vector<Bin> out;
    out.reserve(static_cast<size_t>(n));
    out.resize(static_cast<size_t>(shift));  // `shift` empty bins
    for (long i = 0; i < n - shift; ++i) out.push_back(x[static_cast<size_t>(i)]);
    return out;
}

// _shift_bins_so_t_is_not_past_end
void shift_so_t_not_past_end(std::vector<Bin>& bins, double& last_bin_end,
                             double bin_width, double t) {
    if (bin_width <= 0.0) return;
    long shift = static_cast<long>(std::ceil((t - last_bin_end) / bin_width));
    if (shift < 0) shift = 0;
    if (shift > 0) {
        bins = shift_bins(bins, shift);
        last_bin_end = last_bin_end + shift * bin_width;
    }
}

// combine_bins: union of keys, pairwise (total, count) addition.
Bin combine_bins(const Bin& a, const Bin& b) {
    Bin out = a;
    for (const auto& kv : b) {
        auto& slot = out[kv.first];  // value-inits to (0,0) on insert
        slot.first += kv.second.first;
        slot.second += kv.second.second;
    }
    return out;
}

}  // namespace

Bin keep_largest(const Bin& in, int n, bool has_squash,
                 const std::string& squash_key, bool is_gauge) {
    // Fast path: nothing to trim.
    if (static_cast<int>(in.size()) <= n) return in;

    struct Item {
        std::string key;
        std::pair<double, double> val;
    };
    std::vector<Item> items;
    items.reserve(in.size());
    for (const auto& kv : in) items.push_back(Item{kv.first, kv.second});

    // magnitude used for ordering: mean for gauges, total for rates.
    auto mag = [&](const std::pair<double, double>& v) -> double {
        if (is_gauge) return v.second != 0.0 ? v.first / v.second : 0.0;
        return v.first;
    };
    // p2pool sorts by (k != squash_key, key(v)) reverse=True, i.e. the squash
    // key is ranked LAST (its `k != squash_key` is False) and everything else
    // by descending magnitude. std::stable_sort matches Python's stable sort.
    std::stable_sort(items.begin(), items.end(),
        [&](const Item& x, const Item& y) {
            bool xs = has_squash && x.key != squash_key;
            bool ys = has_squash && y.key != squash_key;
            if (xs != ys) return xs > ys;      // non-squash keys first
            return mag(x.val) > mag(y.val);    // then by descending magnitude
        });

    while (static_cast<int>(items.size()) > n) {
        Item last = items.back();
        items.pop_back();
        if (has_squash && !items.empty()) {
            // Merge the trimmed value into the new last item, RENAMING it to the
            // squash key (p2pool: items[-1] = squash_key, add(items[-1][1], v)).
            Item& tail = items.back();
            tail.key = squash_key;
            tail.val.first += last.val.first;
            tail.val.second += last.val.second;
        }
    }

    Bin out;
    for (const auto& it : items) out[it.key] = it.val;
    return out;
}

// ── DataView ────────────────────────────────────────────────────────────────

void DataView::add_datum(const DataStreamDescription& ds, double t,
                         std::map<std::string, double> value) {
    if (!ds.multivalues) {
        // Scalar streams arrive as {"null": scalar}; nothing to normalize.
    } else if (ds.multivalue_undefined_means_0 && value.find("null") == value.end()) {
        value["null"] = 0.0;  // null holds the sample counter
    }

    shift_so_t_not_past_end(bins, last_bin_end, desc.bin_width, t);

    long bin = static_cast<long>(std::floor((last_bin_end - t) / desc.bin_width));
    if (bin < 0) return;
    if (bin < desc.bin_count) {
        Bin add;
        for (const auto& kv : value) add[kv.first] = {kv.second, 1.0};
        Bin combined = combine_bins(bins[static_cast<size_t>(bin)], add);
        bins[static_cast<size_t>(bin)] = keep_largest(
            combined, ds.multivalues_keep, ds.has_squash_key,
            ds.multivalues_squash_key, ds.is_gauge);
    }
}

nlohmann::json DataView::get_data(const DataStreamDescription& ds, double t) const {
    // Work on shifted copies so the read is const and non-mutating.
    std::vector<Bin> b = bins;
    double lbe = last_bin_end;
    shift_so_t_not_past_end(b, lbe, desc.bin_width, t);

    const double bw = desc.bin_width;

    // Build ascending (oldest-first): p2pool enumerates newest-first (i=0 newest),
    // so we walk i from bin_count-1 down to 0.
    struct Point {
        double center;
        nlohmann::json val;
        double width;
        nlohmann::json def;
        bool empty;
    };
    std::vector<Point> pts;
    pts.reserve(b.size());

    for (long i = desc.bin_count - 1; i >= 0; --i) {
        const Bin& bin = b[static_cast<size_t>(i)];
        double left = lbe - bw * (i + 1);
        double right = std::min(t, lbe - bw * i);
        double center = (left + right) / 2.0;
        double width = right - left;

        nlohmann::json val;
        nlohmann::json def;
        bool empty = bin.empty();

        if (ds.is_gauge && ds.multivalue_undefined_means_0) {
            double real_count = 0.0;
            for (const auto& kv : bin) real_count = std::max(real_count, kv.second.second);
            if (real_count == 0.0) {
                val = nullptr;
                empty = true;
            } else {
                val = nlohmann::json::object();
                for (const auto& kv : bin) val[kv.first] = kv.second.first / real_count;
            }
            def = 0;
        } else if (ds.is_gauge) {
            val = nlohmann::json::object();
            for (const auto& kv : bin) {
                double c = kv.second.second;
                val[kv.first] = c != 0.0 ? kv.second.first / c : 0.0;
            }
            def = nullptr;
        } else {  // rate (not used by c2pool streams; ported for fidelity)
            val = nlohmann::json::object();
            for (const auto& kv : bin) {
                val[kv.first] = width != 0.0 ? kv.second.first / width : 0.0;
            }
            def = 0;
        }

        if (!ds.multivalues) {
            // Reduce to the scalar carried under "null".
            if (val.is_null()) {
                // keep null
            } else if (val.contains("null")) {
                nlohmann::json scalar = val["null"];  // copy before overwrite
                val = std::move(scalar);
            } else {
                val = def;
            }
        } else if (val.is_object() && val.contains("null")) {
            // Never leak the internal sample-counter key into a served dict:
            // dashboard.html sums d[1]['null'] into DOA (renderHashrateGraph).
            val.erase("null");
        }

        pts.push_back(Point{center, std::move(val), width, std::move(def), empty});
    }

    // Clip leading never-filled bins (oldest side) so the frontend never sees a
    // run of nulls before real data begins — matches the flat path's behaviour
    // of emitting only samples that exist.
    size_t start = 0;
    while (start < pts.size() && pts[start].empty) ++start;

    nlohmann::json out = nlohmann::json::array();
    for (size_t i = start; i < pts.size(); ++i) {
        out.push_back(nlohmann::json::array({pts[i].center, pts[i].val,
                                             pts[i].width, pts[i].def}));
    }
    return out;
}

nlohmann::json DataView::to_obj() const {
    nlohmann::json o = nlohmann::json::object();
    o["last_bin_end"] = last_bin_end;
    o["bin_width"] = desc.bin_width;
    nlohmann::json barr = nlohmann::json::array();
    for (const auto& bin : bins) {
        nlohmann::json bo = nlohmann::json::object();
        for (const auto& kv : bin) {
            bo[kv.first] = nlohmann::json::array({kv.second.first, kv.second.second});
        }
        barr.push_back(std::move(bo));
    }
    o["bins"] = std::move(barr);
    return o;
}

// ── DataStream ───────────────────────────────────────────────────────────────

void DataStream::add_multi(double t, const std::map<std::string, double>& value) {
    for (auto& dv : dataviews) dv.second.add_datum(desc, t, value);
}

void DataStream::add_scalar(double t, double value) {
    std::map<std::string, double> v{{"null", value}};
    for (auto& dv : dataviews) dv.second.add_datum(desc, t, v);
}

DataView* DataStream::view(const std::string& name) {
    for (auto& dv : dataviews)
        if (dv.first == name) return &dv.second;
    return nullptr;
}
const DataView* DataStream::view(const std::string& name) const {
    for (const auto& dv : dataviews)
        if (dv.first == name) return &dv.second;
    return nullptr;
}

// ── HistoryDatabase ──────────────────────────────────────────────────────────

HistoryDatabase HistoryDatabase::create(
    const std::vector<std::pair<std::string, DataStreamDescription>>& descs) {
    HistoryDatabase db;
    for (const auto& sd : descs) {
        DataStream ds;
        ds.desc = sd.second;
        for (const auto& dvd : sd.second.dataview_descriptions) {
            std::vector<Bin> empty(static_cast<size_t>(dvd.second.bin_count));
            ds.dataviews.emplace_back(dvd.first, DataView(dvd.second, 0.0, std::move(empty)));
        }
        db.datastreams.emplace_back(sd.first, std::move(ds));
    }
    return db;
}

HistoryDatabase HistoryDatabase::from_obj(
    const std::vector<std::pair<std::string, DataStreamDescription>>& descs,
    const nlohmann::json& obj, bool& needs_reseed) {
    needs_reseed = false;
    HistoryDatabase db;
    for (const auto& sd : descs) {
        DataStream ds;
        ds.desc = sd.second;
        const bool has_stream = obj.is_object() && obj.contains(sd.first)
                                && obj[sd.first].is_object();
        for (const auto& dvd : sd.second.dataview_descriptions) {
            const DataViewDescription& geom = dvd.second;
            bool loaded = false;
            if (has_stream) {
                const nlohmann::json& sdata = obj[sd.first];
                if (sdata.contains(dvd.first) && sdata[dvd.first].is_object()) {
                    const nlohmann::json& vd = sdata[dvd.first];
                    // Geometry validation (review #2): a valid-JSON view with the
                    // wrong bin_width or bin_count is NOT loadable as-is; discard
                    // it and force a reseed rather than serving mismatched bins.
                    const bool width_ok =
                        vd.contains("bin_width") && vd["bin_width"].is_number()
                        && std::fabs(vd["bin_width"].get<double>() - geom.bin_width)
                               <= 1e-6 * std::max(1.0, geom.bin_width);
                    const bool bins_ok =
                        vd.contains("bins") && vd["bins"].is_array()
                        && static_cast<int>(vd["bins"].size()) == geom.bin_count;
                    if (width_ok && bins_ok) {
                        std::vector<Bin> parsed;
                        parsed.reserve(static_cast<size_t>(geom.bin_count));
                        for (const auto& bo : vd["bins"]) {
                            Bin bin;
                            if (bo.is_object()) {
                                for (auto it = bo.begin(); it != bo.end(); ++it) {
                                    if (it.value().is_array() && it.value().size() == 2) {
                                        bin[it.key()] = {it.value()[0].get<double>(),
                                                         it.value()[1].get<double>()};
                                    }
                                }
                            }
                            parsed.push_back(std::move(bin));
                        }
                        double lbe = vd.value("last_bin_end", 0.0);
                        ds.dataviews.emplace_back(dvd.first,
                            DataView(geom, lbe, std::move(parsed)));
                        loaded = true;
                    }
                }
            }
            if (!loaded) {
                needs_reseed = true;
                std::vector<Bin> empty(static_cast<size_t>(geom.bin_count));
                ds.dataviews.emplace_back(dvd.first, DataView(geom, 0.0, std::move(empty)));
            }
        }
        db.datastreams.emplace_back(sd.first, std::move(ds));
    }
    return db;
}

nlohmann::json HistoryDatabase::to_obj() const {
    nlohmann::json o = nlohmann::json::object();
    for (const auto& sd : datastreams) {
        nlohmann::json so = nlohmann::json::object();
        for (const auto& dv : sd.second.dataviews) {
            so[dv.first] = dv.second.to_obj();
        }
        o[sd.first] = std::move(so);
    }
    return o;
}

DataStream* HistoryDatabase::stream(const std::string& name) {
    for (auto& sd : datastreams)
        if (sd.first == name) return &sd.second;
    return nullptr;
}
const DataStream* HistoryDatabase::stream(const std::string& name) const {
    for (const auto& sd : datastreams)
        if (sd.first == name) return &sd.second;
    return nullptr;
}

void HistoryDatabase::add_scalar(const std::string& name, double t, double value) {
    if (auto* s = stream(name)) s->add_scalar(t, value);
}
void HistoryDatabase::add_multi(const std::string& name, double t,
                                const std::map<std::string, double>& value) {
    if (auto* s = stream(name)) s->add_multi(t, value);
}

}  // namespace graph
}  // namespace core
