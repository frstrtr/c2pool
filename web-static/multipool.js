/**
 * P2Pool Multi-Pool Dashboard Support
 * 
 * Enables a single dashboard UI to switch between multiple p2pool instances
 * (e.g., LTC and DGB running on different ports). Pool configurations are
 * stored in localStorage. The active pool's API base URL is used for all
 * d3.json() calls via a transparent override.
 *
 * Usage: Include this script AFTER d3.js but BEFORE any dashboard code.
 *        <script src="multipool.js"></script>
 *
 * The script:
 *  1. Auto-detects the current pool from /web/currency_info
 *  2. Renders pool selector tabs in the #pool-tabs container
 *  3. Overrides d3.json() to prepend the active pool's API base URL
 *  4. Provides pool configuration management (add/remove/switch)
 */
(function() {
    'use strict';

    var STORAGE_KEY = 'p2pool_multipool_config';
    var _origD3Json = d3.json.bind(d3);

    // ── API Base URL ─────────────────────────────────────────────────────
    // Empty string = same origin (default). Set to 'http://host:port' for
    // cross-origin pools (requires CORS headers, already present in web.py).
    window.multipoolApiBase = '';

    // ── d3.json override ─────────────────────────────────────────────────
    // Transparently routes relative API calls (../foo) and absolute path
    // calls (/foo) through the active pool's base URL when cross-origin
    // access is needed.
    d3.json = function(url, callback) {
        var base = window.multipoolApiBase;
        if (base && typeof url === 'string') {
            if (url.indexOf('../') === 0) {
                url = base + '/' + url.substring(3);
            } else if (url.charAt(0) === '/' && url.indexOf('//') !== 0) {
                // Absolute path like /ban_stats → base + /ban_stats
                url = base + url;
            }
        }
        return _origD3Json(url, callback);
    };

    // ── Configuration persistence ────────────────────────────────────────
    function getConfig() {
        try {
            var raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) return { pools: [], activePool: null };
            var cfg = JSON.parse(raw);
            if (!cfg || !Array.isArray(cfg.pools)) return { pools: [], activePool: null };
            return cfg;
        } catch(e) {
            return { pools: [], activePool: null };
        }
    }

    function saveConfig(config) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
    }

    // ── Pool CRUD ────────────────────────────────────────────────────────
    function addPool(id, name, symbol, url, color) {
        var config = getConfig();
        var existing = null;
        for (var i = 0; i < config.pools.length; i++) {
            if (config.pools[i].id === id) { existing = config.pools[i]; break; }
        }
        if (existing) {
            existing.name = name;
            existing.symbol = symbol;
            existing.url = url;
            if (color) existing.color = color;
        } else {
            config.pools.push({
                id: id,
                name: name || symbol,
                symbol: symbol,
                url: url,
                color: color || '#008de4'
            });
        }
        saveConfig(config);
        return config;
    }

    // ── Pool switching ───────────────────────────────────────────────────
    function switchToPool(poolId) {
        var config = getConfig();
        var pool = null;
        for (var i = 0; i < config.pools.length; i++) {
            if (config.pools[i].id === poolId) { pool = config.pools[i]; break; }
        }
        if (!pool) return;

        config.activePool = poolId;
        saveConfig(config);

        if (window._multipoolProxyMode) {
            // In proxy mode, always use the proxy API route
            window.multipoolApiBase = '/api/' + poolId;
        } else {
            // In direct mode, check if this pool is the current page's origin
            var currentOrigin = window.location.protocol + '//' + window.location.host;
            if (pool.url === currentOrigin || pool.url === '') {
                window.multipoolApiBase = '';
            } else {
                window.multipoolApiBase = pool.url;
            }
        }

        // Update UI
        renderTabs();

        // Refresh the dashboard data by reloading currency_info first,
        // then triggering a full data refresh.
        reloadCurrencyAndRefresh();
    }

    // ── Reload currency info and trigger full refresh ────────────────────
    function reloadCurrencyAndRefresh() {
        d3.json('../web/currency_info', function(info) {
            // Update global currency_info if it exists
            if (typeof window.currency_info !== 'undefined') {
                window.currency_info = info || {};
            }
            if (info) {
                var sym = info.symbol || 'COIN';
                var chainName = info.name || sym;
                d3.selectAll('.symbol-small').text(sym);
                d3.select('#currency-symbol').text(sym);
                d3.selectAll('.parent-symbol-hint').text(sym + '_ADDR');
                if (document.getElementById('parent_chain_peers_title'))
                    d3.select('#parent_chain_peers_title').text(chainName);
                if (info.block_period && typeof window.parentBlockPeriodMs !== 'undefined') {
                    window.parentBlockPeriodMs = info.block_period * 1000;
                }
                // Update page title
                document.title = 'c2pool ' + sym + ' Dashboard';
            }
        });

        // Reload version
        d3.json('../web/version', function(version) {
            if (version) {
                d3.select('#version').text(version);
                d3.select('#footer_version').text(version);
            }
        });

        // Reload node info (stratum URL)
        d3.json('../node_info', function(nodeInfo) {
            var el = document.getElementById('miner-url');
            if (el) {
                if (nodeInfo && nodeInfo.external_ip) {
                    el.textContent = 'stratum+tcp://' + nodeInfo.external_ip + ':' + nodeInfo.worker_port;
                } else {
                    el.textContent = 'unavailable';
                }
            }
        });

        // Trigger full data refresh (dashboard-specific functions)
        setTimeout(function() {
            if (typeof manualRefresh === 'function') {
                manualRefresh();
            }
            // For graphs page
            if (typeof loadHashrateGraph === 'function') {
                loadHashrateGraph();
            }
        }, 200);
    }

    // ── Color palette for chains ─────────────────────────────────────────
    var CHAIN_COLORS = {
        'ltc': '#345d9d',
        'dgb': '#0066cc',
        'btc': '#f7931a',
        'doge': '#c3a634',
        'bch': '#0ac18e',
        'dash': '#008de4',
        'zec': '#ecb244'
    };

    function getChainColor(symbol) {
        if (!symbol) return '#008de4';
        var key = symbol.toLowerCase();
        return CHAIN_COLORS[key] || '#008de4';
    }

    // ── Tab rendering ────────────────────────────────────────────────────
    function renderTabs() {
        var config = getConfig();
        var container = document.getElementById('pool-tabs');
        if (!container) return;
        container.innerHTML = '';

        // Sort pools: active first, then alphabetical
        var sorted = config.pools.slice().sort(function(a, b) {
            if (a.id === config.activePool) return -1;
            if (b.id === config.activePool) return 1;
            return a.symbol.localeCompare(b.symbol);
        });

        sorted.forEach(function(pool) {
            var tab = document.createElement('span');
            var isActive = pool.id === config.activePool;
            tab.className = 'pool-tab' + (isActive ? ' active' : '');
            tab.textContent = pool.symbol;
            tab.dataset.poolId = pool.id;
            tab.title = pool.name + ' — ' + (pool.url || 'this node');

            if (isActive) {
                tab.style.backgroundColor = pool.color || getChainColor(pool.symbol);
                tab.style.borderColor = pool.color || getChainColor(pool.symbol);
            }

            tab.addEventListener('click', function() {
                if (pool.id !== config.activePool) {
                    switchToPool(pool.id);
                }
            });

            container.appendChild(tab);
        });
    }

    // ── Proxy mode flag ──────────────────────────────────────────────────
    window._multipoolProxyMode = false;

    // ── Auto-detect: try proxy first, then direct ────────────────────────
    function autoDetectCurrentPool() {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', '/api/pools', true);
        xhr.timeout = 3000;
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    var pools = JSON.parse(xhr.responseText);
                    if (Array.isArray(pools) && pools.length > 0) {
                        initFromProxy(pools);
                        return;
                    }
                } catch(e) {}
            }
            initFromDirect();
        };
        xhr.onerror = function() { initFromDirect(); };
        xhr.ontimeout = function() { initFromDirect(); };
        xhr.send();
    }

    function initFromProxy(proxyPools) {
        window._multipoolProxyMode = true;

        // Register all pools from proxy with their backend URLs (for display)
        proxyPools.forEach(function(pool) {
            addPool(pool.id, pool.name, pool.symbol,
                    pool.direct_url || pool.url, pool.color);
        });

        var config = getConfig();
        // Set active pool if not set or if stored pool no longer exists
        var activeExists = config.activePool && config.pools.some(function(p) {
            return p.id === config.activePool;
        });
        if (!activeExists) {
            config.activePool = proxyPools[0].id;
            saveConfig(config);
        }

        // Set API base to the active pool's proxy route
        window.multipoolApiBase = '/api/' + config.activePool;

        renderTabs();

        // Refresh data through the correct proxy route
        reloadCurrencyAndRefresh();
    }

    function initFromDirect() {
        var currentOrigin = window.location.protocol + '//' + window.location.host;

        _origD3Json('../web/currency_info', function(info) {
            if (!info || !info.symbol) return;

            var poolId = info.symbol.toLowerCase();
            addPool(poolId, info.name || info.symbol, info.symbol, currentOrigin, getChainColor(info.symbol));

            var config = getConfig();
            if (!config.activePool) {
                config.activePool = poolId;
                saveConfig(config);
            }

            if (config.activePool !== poolId) {
                var activePool = null;
                for (var i = 0; i < config.pools.length; i++) {
                    if (config.pools[i].id === config.activePool) {
                        activePool = config.pools[i];
                        break;
                    }
                }
                if (activePool && activePool.url !== currentOrigin) {
                    window.multipoolApiBase = activePool.url;
                }
            }

            renderTabs();
        });
    }

    // ── Initialize on DOM ready ──────────────────────────────────────────
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', autoDetectCurrentPool);
    } else {
        autoDetectCurrentPool();
    }

    // ── Public API ───────────────────────────────────────────────────────
    window.multipool = {
        getConfig: getConfig,
        saveConfig: saveConfig,
        addPool: addPool,
        switchToPool: switchToPool,
        renderTabs: renderTabs,
        getChainColor: getChainColor
    };

})();
