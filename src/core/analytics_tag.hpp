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
// - Consent Mode: every storage type defaults to denied (cookieless pings
//   only). A small bar before </body> asks; Accept grants analytics_storage
//   only (never an ad_* type), Decline keeps it denied. The choice is kept in
//   localStorage under c2pool_ga_consent; a stored "granted" is restored in
//   <head> before the config call, and a stored choice hides the bar.
// - A page without </head> is left unchanged. A page without </body> gets the
//   <head> part only, with consent left denied (no bar, no restore). A page
//   that already carries the tag (or its own gtag.js) is left unchanged.
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

/// The <head> part: consent defaults (all denied), the stored-choice restore
/// when the page also gets the consent bar, gtag.js, then the config call.
/// `id` must be valid (inject_analytics_tag checks it).
inline std::string analytics_head_snippet(const std::string& id, bool restore_choice)
{
    std::string s;
    s += kAnalyticsMarker;
    s += "\n<script>\n"
         "window.dataLayer=window.dataLayer||[];\n"
         "function gtag(){dataLayer.push(arguments);}\n"
         "gtag('consent','default',{analytics_storage:'denied',ad_storage:'denied',"
         "ad_user_data:'denied',ad_personalization:'denied'});\n";
    if (restore_choice) {
        s += "try{if(window.localStorage.getItem('";
        s += kAnalyticsConsentKey;
        s += "')==='granted'){gtag('consent','update',{analytics_storage:'granted'});}}catch(e){}\n";
    }
    s += "</script>\n"
         "<script async src=\"https://www.googletagmanager.com/gtag/js?id=";
    s += id;
    s += "\"></script>\n"
         "<script>\n"
         "gtag('js',new Date());\n"
         "gtag('config','";
    s += id;
    s += "');\n"
         "</script>\n";
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
         "if(c==='granted'&&typeof gtag==='function'){gtag('consent','update',{analytics_storage:'granted'});}\n"
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
