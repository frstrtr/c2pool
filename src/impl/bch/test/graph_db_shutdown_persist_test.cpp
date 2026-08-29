// B-STATS.944 -- BCH graph_db stat-log save-on-clean-shutdown proof.
//
// pool_entrypoint.hpp stands up graph_db persistence with three call sites:
//   site 1  load_stat_log()  once at standup            (load-on-start)
//   site 2  save_stat_log()  periodic every 100s        (steady-state tick)
//   site 3  save_stat_log()  once after ioc.run() returns on a CLEAN shutdown
// Site 3 was the last lane gap (BTC #1100 / DGB #1097 already landed it). This
// KAT proves its contract: a save-on-shutdown flush followed by a fresh
// process load-on-start round-trips the SAME entry count -- i.e.
// Saved N == Loaded N across a graceful stop, without waiting for a 100s tick.
// The DASH D-STATS.944 runtime bar was Saved 5 == Loaded 5; we hold the same N.
//
// A graceful stop is modelled by DESTROYING the first MiningInterface (the one
// that ran the loop and flushed on shutdown) and constructing a fresh one that
// loads from the same path -- exactly what a process restart does. SIGKILL is
// out of scope: it flushes neither lane, matching the entrypoint precondition.
//
// m_stat_log has no public size getter and we add NONE (that would be a core
// edit); instead we count entries on disk via the JSON the save path writes,
// and prove the loaded set by re-flushing it to a second path and counting that.
//
// Isolation: test-only, src/impl/bch/test. Links core (the monolithic OBJECT lib
// that carries web_server.cpp) exactly as the sibling BCH tests do; it does NOT
// edit core and does NOT touch any other coin tree.

#include <core/web_server.hpp>

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include <nlohmann/json.hpp>

static std::size_t file_entry_count(const std::string& path)
{
    std::ifstream f(path);
    assert(f && "stat-log file must exist after save");
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    auto arr = nlohmann::json::parse(content);
    assert(arr.is_array() && "stat-log file must be a JSON array");
    return arr.size();
}

int main()
{
    const int N = 5;  // DASH D-STATS.944 bar: Saved 5 == Loaded 5

    auto dir = std::filesystem::temp_directory_path() / "bch_graph_db_shutdown_kat";
    std::filesystem::create_directories(dir);
    const std::string saved_path  = (dir / "graph_db").string();
    const std::string reload_path = (dir / "graph_db.reload").string();
    for (const auto& p : {saved_path, saved_path + ".new", reload_path, reload_path + ".new"})
        std::filesystem::remove(p);

    // --- Run #1: accumulate N entries, then flush on "clean shutdown" (site 3). ---
    std::size_t saved_n = 0;
    {
        core::MiningInterface mi_run1(/*testnet=*/false, /*node=*/nullptr,
                                      c2pool::address::Blockchain::BITCOIN);
        mi_run1.set_stat_log_path(saved_path);
        for (int i = 0; i < N; ++i)
            mi_run1.update_stat_log();   // one entry per periodic sample
        mi_run1.save_stat_log();         // <-- the site-3 clean-shutdown flush
        saved_n = file_entry_count(saved_path);
        std::cout << "[B-STATS.944] Saved " << saved_n << " entries to "
                  << saved_path << "\n";
        // mi_run1 destroyed here == graceful process exit AFTER the flush.
    }
    assert(saved_n == static_cast<std::size_t>(N) &&
           "shutdown flush must persist all N accumulated entries");

    // --- Run #2: fresh process loads the flushed log (site 1). ---
    std::size_t loaded_n = 0;
    {
        core::MiningInterface mi_run2(/*testnet=*/false, /*node=*/nullptr,
                                      c2pool::address::Blockchain::BITCOIN);
        mi_run2.set_stat_log_path(saved_path);
        mi_run2.load_stat_log();         // <-- load-on-start
        // Re-flush to a second path to count what was actually loaded into
        // memory (no public size getter; we add none to keep core untouched).
        mi_run2.set_stat_log_path(reload_path);
        mi_run2.save_stat_log();
        loaded_n = file_entry_count(reload_path);
        std::cout << "[B-STATS.944] Loaded " << loaded_n << " entries from "
                  << saved_path << "\n";
    }

    assert(loaded_n == saved_n && "Loaded count must equal Saved count");
    std::cout << "[B-STATS.944] PASS: Saved " << saved_n
              << " == Loaded " << loaded_n << " across a graceful stop\n";

    for (const auto& p : {saved_path, saved_path + ".new", reload_path, reload_path + ".new"})
        std::filesystem::remove(p);
    return 0;
}
