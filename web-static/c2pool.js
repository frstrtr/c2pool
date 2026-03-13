/**
 * c2pool API client — universal dashboard gate
 *
 * Provides a single C2PoolAPI object that wraps both the native c2pool
 * REST endpoints AND the legacy p2pool endpoints, giving dashboard
 * authors a stable abstraction.
 *
 * Lineage: p2pool/p2pool → jtoomim/p2pool → frstrtr/c2pool
 */

"use strict";

const C2PoolAPI = (() => {
    const BASE = "";  // same-origin; override for cross-origin setups

    async function fetchJSON(path) {
        const resp = await fetch(BASE + path);
        if (!resp.ok) return null;
        return resp.json();
    }

    async function fetchText(path) {
        const resp = await fetch(BASE + path);
        if (!resp.ok) return null;
        return resp.text();
    }

    // ── Native c2pool endpoints ────────────────────────────────
    const localRate    = () => fetchJSON("/local_rate");
    const globalRate   = () => fetchJSON("/global_rate");
    const payouts      = () => fetchJSON("/current_payouts");
    const users        = () => fetchJSON("/users");
    const fee          = () => fetchJSON("/fee");
    const recentBlocks = () => fetchJSON("/recent_blocks");
    const uptime       = () => fetchJSON("/uptime");
    const miners       = () => fetchJSON("/connected_miners");
    const stratumStats = () => fetchJSON("/stratum_stats");
    const globalStats  = () => fetchJSON("/global_stats");
    const sharechainStats  = () => fetchJSON("/sharechain/stats");
    const sharechainWindow = () => fetchJSON("/sharechain/window");
    const webLog       = () => fetchText("/web/log");

    // ── p2pool legacy compatibility endpoints ──────────────────
    const localStats       = () => fetchJSON("/local_stats");
    const p2poolGlobalStats = () => fetchJSON("/p2pool_global_stats");
    const version          = () => fetchJSON("/web/version");
    const currencyInfo     = () => fetchJSON("/web/currency_info");
    const payoutAddr       = () => fetchJSON("/payout_addr");
    const payoutAddrs      = () => fetchJSON("/payout_addrs");
    const bestShareHash    = () => fetchJSON("/web/best_share_hash");

    // ── Control endpoints ──────────────────────────────────────
    const controlStart   = () => fetchJSON("/control/mining/start");
    const controlStop    = () => fetchJSON("/control/mining/stop");
    const controlRestart = () => fetchJSON("/control/mining/restart");

    // ── Convenience: fetch everything in parallel ──────────────
    async function fetchAll() {
        const [lr, gr, pys, u, f, rb, ut, mn, ss, gs, sc, ci] = await Promise.allSettled([
            localRate(), globalRate(), payouts(), users(), fee(),
            recentBlocks(), uptime(), miners(), stratumStats(),
            globalStats(), sharechainStats(), currencyInfo()
        ]);
        return {
            localRate:    lr.status === "fulfilled" ? lr.value : null,
            globalRate:   gr.status === "fulfilled" ? gr.value : null,
            payouts:      pys.status === "fulfilled" ? pys.value : null,
            users:        u.status === "fulfilled" ? u.value : null,
            fee:          f.status === "fulfilled" ? f.value : null,
            recentBlocks: rb.status === "fulfilled" ? rb.value : null,
            uptime:       ut.status === "fulfilled" ? ut.value : null,
            miners:       mn.status === "fulfilled" ? mn.value : null,
            stratumStats: ss.status === "fulfilled" ? ss.value : null,
            globalStats:  gs.status === "fulfilled" ? gs.value : null,
            sharechainStats: sc.status === "fulfilled" ? sc.value : null,
            currencyInfo: ci.status === "fulfilled" ? ci.value : null,
        };
    }

    // ── Helpers ────────────────────────────────────────────────
    function formatHashrate(h) {
        if (h == null || isNaN(h)) return "—";
        const units = ["H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];
        let i = 0;
        while (h >= 1000 && i < units.length - 1) { h /= 1000; i++; }
        return h.toFixed(2) + " " + units[i];
    }

    function formatDuration(seconds) {
        if (seconds == null) return "—";
        const d = Math.floor(seconds / 86400);
        const h = Math.floor((seconds % 86400) / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        if (d > 0) return d + "d " + h + "h";
        if (h > 0) return h + "h " + m + "m";
        if (m > 0) return m + "m " + s + "s";
        return s + "s";
    }

    function formatCoins(satoshis, decimals) {
        if (satoshis == null) return "—";
        if (decimals === undefined) decimals = 8;
        return (satoshis / 1e8).toFixed(decimals);
    }

    function timeAgo(ts) {
        const diff = Math.floor(Date.now() / 1000) - ts;
        return formatDuration(diff) + " ago";
    }

    return {
        // Native endpoints
        localRate, globalRate, payouts, users, fee, recentBlocks, uptime,
        miners, stratumStats, globalStats, sharechainStats, sharechainWindow,
        webLog,
        // Legacy p2pool endpoints
        localStats, p2poolGlobalStats: p2poolGlobalStats, version, currencyInfo,
        payoutAddr, payoutAddrs, bestShareHash,
        // Control
        controlStart, controlStop, controlRestart,
        // Batch
        fetchAll,
        // Helpers
        formatHashrate, formatDuration, formatCoins, timeAgo,
        // Low-level
        fetchJSON, fetchText
    };
})();
