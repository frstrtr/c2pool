// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Google Analytics tag a node puts in the HTML pages it serves
// (--analytics-id ID, settings key web.analytics_id; default empty = off).
//
// - The ID is written into a script and a URL, so only a measurement ID is
//   accepted: GA4 "G-" + 4..20 of [A-Z0-9], or the legacy Universal
//   Analytics "UA-<4..10 digits>-<1..4 digits>". A bad command-line value
//   refuses the start; a bad settings-file value is warned about and ignored;
//   inject_analytics_tag() checks it again and puts nothing in for a bad one.
// - Consent Mode: every storage type defaults to denied. A small bar before
//   </body> asks; Accept grants analytics_storage only (never an ad_* type),
//   Decline keeps it denied. The choice is kept in localStorage under
//   c2pool_ga_consent; a stored "granted" is restored on load, and a stored
//   choice hides the bar.
// - No contact with Google before consent: the page carries no external
//   script. Only once consent is granted (Accept, or a stored "granted" on
//   load) does it create the one gtag.js script element (no referrer) and
//   queue the consent default, the update, the config call (send_page_view
//   false) and the one page_view. Decline, or no answer, never loads it.
// - No address reaches Google: page_location / page_path / page_referrer /
//   page_title are sent explicitly, built from location.pathname with the
//   query string and fragment dropped and every address-like path segment
//   (or the segment after a per-miner route) replaced by ":addr"
//   (analytics_sanitize_path is the same rule in C++). The page's referrer
//   policy becomes no-referrer, so no request carries the raw URL either.
// - A page without </head> is left unchanged. A page without </body> gets the
//   <head> part only, with consent left denied (no bar, no restore, nothing
//   sent). A page that already carries the tag (or its own gtag.js) is left
//   unchanged. analytics_allowed_target() keeps the tag off /control/*,
//   /api/*, /web/log, /logs/* and any request that carries a token.
//
// explorer/explorer.py builds the same bytes for its generated pages
// (core_test checks the two against each other).
#pragma once

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

#include <core/log.hpp>

namespace core {

inline constexpr std::string_view kAnalyticsMarker = "<!-- c2pool-analytics -->";
inline constexpr std::string_view kAnalyticsConsentMarker = "<!-- c2pool-analytics-consent -->";
inline constexpr std::string_view kAnalyticsConsentKey = "c2pool_ga_consent";

namespace analytics_detail {

inline bool all_of_class(std::string_view s, bool digits_only)
{
    for (char c : s) {
        const bool digit = c >= '0' && c <= '9';
        const bool upper = c >= 'A' && c <= 'Z';
        if (!(digit || (!digits_only && upper)))
            return false;
    }
    return true;
}

// First (or last) position of `needle` in `hay`, ASCII case-insensitive.
inline std::size_t find_ci(std::string_view hay, std::string_view needle, bool last)
{
    if (needle.empty() || hay.size() < needle.size())
        return std::string::npos;
    const std::size_t n = hay.size() - needle.size() + 1;
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t i = last ? n - 1 - k : k;
        bool eq = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            const auto a = static_cast<unsigned char>(hay[i + j]);
            const auto b = static_cast<unsigned char>(needle[j]);
            if (std::tolower(a) != std::tolower(b)) {
                eq = false;
                break;
            }
        }
        if (eq)
            return i;
    }
    return std::string::npos;
}

} // namespace analytics_detail

/// The path sanitizer the snippet runs in the browser (JavaScript). The C++
/// port below is the same rule; core_test runs this text under node, when
/// it is installed, and checks the two agree.
inline constexpr std::string_view kAnalyticsPathJs =
    "function c2poolGaPath(p){var s=String(p||'/').split('/');"
    "for(var i=1;i<s.length;i++){"
    "if(/[a-z0-9]{20,}/i.test(s[i])"
    "||(s[i]!==''&&/miner|payout|addr|user|worker|patron/i.test(s[i-1]))){s[i]=':addr';}}"
    "return s.join('/')||'/';}";

namespace analytics_detail {

inline bool is_alnum(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

inline std::size_t alnum_run(std::string_view s, std::size_t from)
{
    std::size_t n = 0;
    while (from + n < s.size() && is_alnum(s[from + n]))
        ++n;
    return n;
}

// /[a-z0-9]{20,}/i : a run of 20 or more letters and digits anywhere in the
// segment (base58, bech32, cashaddr after its "prefix:", "ADDR.worker").
inline bool looks_like_address(std::string_view seg)
{
    for (std::size_t i = 0; i < seg.size(); ++i)
        if (alnum_run(seg, i) >= 20)
            return true;
    return false;
}

// /miner|payout|addr|user|worker|patron/i
inline bool names_miner_route(std::string_view seg)
{
    std::string l(seg);
    for (auto& c : l)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (const char* w : {"miner", "payout", "addr", "user", "worker", "patron"})
        if (l.find(w) != std::string::npos)
            return true;
    return false;
}

} // namespace analytics_detail

/// The path GA is given for a page URL path: the query string and fragment
/// dropped, and every segment that looks like an address (it holds a run of
/// 20 or more letters and digits), or that follows a segment
/// naming a per-miner route (miner, payout, addr, user, worker, patron),
/// replaced by ":addr". "/miner_payouts/LVyp..." -> "/miner_payouts/:addr",
/// "/miner.html?address=LVyp..." -> "/miner.html". Same rule as
/// kAnalyticsPathJs.
inline std::string analytics_sanitize_path(std::string_view path)
{
    using namespace analytics_detail;
    const auto cut = path.find_first_of("?#");
    if (cut != std::string_view::npos)
        path = path.substr(0, cut);
    if (path.empty())
        return "/";
    std::string out;
    std::string_view prev;
    std::size_t start = 0;
    for (std::size_t i = 0;; ++i) {
        const std::size_t slash = path.find('/', start);
        const std::string_view seg = path.substr(start, slash == std::string_view::npos
                                                            ? std::string_view::npos
                                                            : slash - start);
        if (i > 0)
            out += '/';
        // As in the script, the previous segment is tested as written out
        // (so one after a replaced segment is replaced too).
        const bool hide = i > 0 && (looks_like_address(seg) || (!seg.empty() && names_miner_route(prev)));
        prev = hide ? std::string_view(":addr") : seg;
        out += prev;
        if (slash == std::string_view::npos)
            break;
        start = slash + 1;
    }
    return out.empty() ? std::string("/") : out;
}

/// Whether a request may get the tag at all: never on /control/*, /api/*
/// (admin, config, tx-inject, explorer API), /web/log or /logs/*, and never
/// on a request whose query carries a token (a page served behind the auth
/// or control token). `path` is the request path, `query` the text after '?'.
inline bool analytics_allowed_target(std::string_view path, std::string_view query)
{
    auto starts = [&](std::string_view p) { return path.substr(0, p.size()) == p; };
    if (starts("/control/") || path == "/control" || starts("/api/") || path == "/api"
        || path == "/web/log" || starts("/logs/") || path == "/logs")
        return false;
    std::size_t at = 0;
    while (at <= query.size()) {
        auto end = query.find('&', at);
        if (end == std::string_view::npos)
            end = query.size();
        std::string key(query.substr(at, end - at));
        key = key.substr(0, key.find('='));
        for (auto& c : key)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (key.find("token") != std::string::npos)
            return false;
        at = end + 1;
    }
    return true;
}

/// A measurement ID the node will put in a page: "G-" + 4..20 of [A-Z0-9],
/// or "UA-" + 4..10 digits + "-" + 1..4 digits. Nothing else.
inline bool is_valid_analytics_id(std::string_view id)
{
    using analytics_detail::all_of_class;
    if (id.substr(0, 2) == "G-") {
        const auto rest = id.substr(2);
        return rest.size() >= 4 && rest.size() <= 20 && all_of_class(rest, false);
    }
    if (id.substr(0, 3) == "UA-") {
        const auto rest = id.substr(3);
        const auto dash = rest.find('-');
        if (dash == std::string_view::npos)
            return false;
        const auto account = rest.substr(0, dash);
        const auto property = rest.substr(dash + 1);
        return account.size() >= 4 && account.size() <= 10 && all_of_class(account, true)
            && property.size() >= 1 && property.size() <= 4 && all_of_class(property, true);
    }
    return false;
}

/// --analytics-id ID: "" (off) or a measurement ID sets `out`. false for
/// anything else (`out` unchanged): the caller refuses to start.
inline bool parse_analytics_id(std::string_view value, std::string& out)
{
    if (!value.empty() && !is_valid_analytics_id(value))
        return false;
    out = std::string(value);
    return true;
}

/// A settings-file value (web.analytics_id, or the LTC YAML analytics_id):
/// "" or a measurement ID sets `out`; anything else is warned about and
/// ignored (`out` keeps the value it had).
inline bool apply_analytics_id_setting(const std::string& key, const std::string& value,
                                       std::string& out)
{
    if (parse_analytics_id(value, out))
        return true;
    LOG_WARNING << "settings: " << key << " = '" << value
                << "' is not a Google Analytics measurement ID (G-XXXXXXXXXX): ignored, "
                   "the analytics tag stays "
                << (out.empty() ? std::string("off") : out);
    return false;
}

/// The process's --analytics-id, for coin mains whose web server is set up
/// far from the command-line parse: the parse (and the settings-file
/// overlay) writes it, the web server wiring reads it. Default "" (off).
inline std::string& analytics_id_setting()
{
    static std::string id;
    return id;
}

/// The <head> part: the no-referrer policy, the dataLayer / gtag stubs, the
/// path sanitizer and the start function. Nothing here contacts Google: the
/// start function, run only once consent is granted, creates the one gtag.js
/// script element, then queues the consent default (all denied), the
/// analytics_storage grant, the config call (send_page_view false) and the
/// one page_view with the sanitized location, path, referrer and title.
/// With `restore_choice` (the page also gets the consent bar) a stored
/// "granted" starts it on load. `id` must be valid (inject_analytics_tag
/// checks it).
inline std::string analytics_head_snippet(const std::string& id, bool restore_choice)
{
    std::string s;
    s += kAnalyticsMarker;
    s += "\n<meta name=\"referrer\" content=\"no-referrer\">\n"
         "<script>\n"
         "window.dataLayer=window.dataLayer||[];\n"
         "function gtag(){dataLayer.push(arguments);}\n";
    s += kAnalyticsPathJs;
    s += "\n"
         "function c2poolGaStart(){\n"
         "if(window.c2poolGaStarted){return;}\n"
         "window.c2poolGaStarted=true;\n"
         "var g=document.createElement('script');\n"
         "g.async=true;\n"
         "g.setAttribute('referrerpolicy','no-referrer');\n"
         "g.src='https://www.googletagmanager.com/gtag/js?id=";
    s += id;
    s += "';\n"
         "(document.head||document.documentElement).appendChild(g);\n"
         "gtag('consent','default',{analytics_storage:'denied',ad_storage:'denied',"
         "ad_user_data:'denied',ad_personalization:'denied'});\n"
         "gtag('consent','update',{analytics_storage:'granted'});\n"
         "gtag('js',new Date());\n"
         "var p=c2poolGaPath(location.pathname),r='';\n"
         "try{if(document.referrer){var u=new URL(document.referrer);r=u.origin+c2poolGaPath(u.pathname);}}"
         "catch(e){r='(unknown)';}\n"
         "var t=String(document.title||'').replace(/[a-z0-9]{20,}/ig,':addr');\n"
         "var v={page_location:location.origin+p,page_path:p,page_referrer:r,page_title:t};\n"
         "gtag('config','";
    s += id;
    s += "',{send_page_view:false,page_location:v.page_location,page_path:p,page_referrer:r,page_title:t});\n"
         "gtag('event','page_view',v);\n"
         "}\n";
    if (restore_choice) {
        s += "try{if(window.localStorage.getItem('";
        s += kAnalyticsConsentKey;
        s += "')==='granted'){c2poolGaStart();}}catch(e){}\n";
    }
    s += "</script>\n";
    return s;
}

/// The consent bar, put before </body>: dark text on a light bar, shown only
/// while no choice is stored, gone after either button. A spacer of its
/// height keeps the end of the page scrollable above it.
inline std::string analytics_consent_banner()
{
    std::string s;
    s += kAnalyticsConsentMarker;
    s += "\n"
         "<div id=\"c2pool-ga-consent\" role=\"region\" aria-label=\"Analytics consent\" "
         "style=\"display:none;position:fixed;left:8px;right:8px;bottom:8px;z-index:2147483647;"
         "box-sizing:border-box;max-width:560px;margin:0 auto;padding:6px 10px;"
         "align-items:center;flex-wrap:wrap;gap:6px 12px;"
         "background:#f5f5f5;color:#111;border:1px solid #777;border-radius:6px;"
         "box-shadow:0 2px 8px rgba(0,0,0,.35);"
         "font:13px/1.4 -apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;text-align:left\">\n"
         "<span style=\"flex:1 1 auto;color:#111\">This site uses Google Analytics cookies to count visits.</span>\n"
         "<span style=\"display:inline-flex;gap:6px\">"
         "<button type=\"button\" data-c2pool-ga=\"granted\" "
         "style=\"margin:0;padding:3px 12px;border:1px solid #111;border-radius:4px;"
         "background:#111;color:#fff;font:inherit;font-weight:600;cursor:pointer\">Accept</button>"
         "<button type=\"button\" data-c2pool-ga=\"denied\" "
         "style=\"margin:0;padding:3px 12px;border:1px solid #777;border-radius:4px;"
         "background:#fff;color:#111;font:inherit;cursor:pointer\">Decline</button>"
         "</span>\n"
         "</div>\n"
         "<script>\n"
         "(function(){\n"
         "var k='";
    s += kAnalyticsConsentKey;
    s += "',bar=document.getElementById('c2pool-ga-consent'),v=null,pad=null;\n"
         "if(!bar){return;}\n"
         "try{v=window.localStorage.getItem(k);}catch(e){}\n"
         "if(v==='granted'||v==='denied'){bar.parentNode.removeChild(bar);return;}\n"
         "function pick(c){\n"
         "try{window.localStorage.setItem(k,c);}catch(e){}\n"
         "if(c==='granted'&&typeof c2poolGaStart==='function'){c2poolGaStart();}\n"
         "if(pad&&pad.parentNode){pad.parentNode.removeChild(pad);}\n"
         "if(bar.parentNode){bar.parentNode.removeChild(bar);}\n"
         "}\n"
         "var b=bar.getElementsByTagName('button');\n"
         "for(var i=0;i<b.length;i++){b[i].onclick=function(){pick(this.getAttribute('data-c2pool-ga'));};}\n"
         "bar.style.display='flex';\n"
         "pad=document.createElement('div');\n"
         "pad.style.height=(bar.offsetHeight+16)+'px';\n"
         "bar.parentNode.insertBefore(pad,bar);\n"
         "})();\n"
         "</script>\n";
    return s;
}

/// Put the tag in one HTML page, at most once: the <head> part before the
/// first </head>, the consent bar before the last </body>. Returns true when
/// the page was changed. Nothing is put in for an empty or invalid `id`, a
/// page without </head>, or a page that already carries a gtag.js tag.
inline bool inject_analytics_tag(std::string& html, const std::string& id)
{
    using analytics_detail::find_ci;
    if (id.empty() || !is_valid_analytics_id(id))
        return false;
    if (html.find(kAnalyticsMarker) != std::string::npos
        || html.find("googletagmanager.com/gtag/js") != std::string::npos)
        return false;
    const std::size_t head = find_ci(html, "</head>", false);
    if (head == std::string::npos)
        return false;
    std::size_t body = find_ci(html, "</body>", true);
    if (body != std::string::npos && body < head)
        body = std::string::npos;
    // The later position first, so `head` stays where it was.
    if (body != std::string::npos)
        html.insert(body, analytics_consent_banner());
    html.insert(head, analytics_head_snippet(id, body != std::string::npos));
    return true;
}

} // namespace core
