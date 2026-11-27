// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The Google Analytics tag in served HTML (core/analytics_tag.hpp):
// - inject_analytics_tag(): once before </head>, the consent bar once before
//   </body>, nothing for an empty or bad ID, a page without </head> unchanged,
//   a page without </body> gets the <head> part only with consent left denied;
// - Consent Mode: default denied for every storage type before the config
//   call, and no ad_* type is ever granted;
// - the ID check (CLI refuses, settings file warns and ignores);
// - a real WebServer serves the tag in its static .html pages only;
// - each coin binary's --analytics-id / web.analytics_id reaches its web
//   server (source wiring) and the catalog row is there for every binary,
//   default off;
// - privacy: never on /control/*, /api/*, /web/log, /logs/*, a request with
//   a token, or a non-HTML file; page views only, after consent; no address
//   or query string reaches Google (the path sanitizer in the snippet, its
//   C++ port, and the snippet itself run under node when it is installed);
// - explorer/explorer.py's generated pages carry the same bytes (run with
//   python3 when it is installed).
#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#ifndef _WIN32
#include <sys/wait.h>
#endif

#include <nlohmann/json.hpp>

#include <core/analytics_tag.hpp>
#include <core/param_catalog.hpp>
#include <core/settings_cli.hpp>
#include <core/settings_file.hpp>
#include <core/web_server.hpp>

#ifndef C2POOL_SRC_ROOT
#error "C2POOL_SRC_ROOT must be defined for the source-wiring KAT"
#endif

namespace {

namespace fs    = std::filesystem;
namespace net   = boost::asio;
namespace beast = boost::beast;
namespace http  = boost::beast::http;
using tcp = boost::asio::ip::tcp;

const std::string kId = "G-TEST1234";

const std::string kPage =
    "<!DOCTYPE html>\n<html><head>\n<meta charset=\"utf-8\"><title>t</title>\n</head>\n"
    "<body>\n<p>page</p>\n</body>\n</html>\n";

std::size_t count(const std::string& hay, const std::string& needle)
{
    std::size_t n = 0;
    for (auto p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + needle.size()))
        ++n;
    return n;
}

std::string slurp(const fs::path& p)
{
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

// Whitespace runs collapsed to one space, so a call split over lines matches.
std::string squash(const std::string& s)
{
    std::string out;
    bool ws = false;
    for (char c : s) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            ws = true;
            continue;
        }
        if (ws && !out.empty())
            out += ' ';
        ws = false;
        out += c;
    }
    return out;
}

std::string src(const std::string& rel)
{
    const std::string text = slurp(fs::path(C2POOL_SRC_ROOT) / rel);
    EXPECT_FALSE(text.empty()) << "cannot read " << rel;
    return squash(text);
}

fs::path make_temp_dir(const std::string& tag)
{
    const auto base = fs::temp_directory_path();
    for (int i = 0; i < 1000; ++i) {
        fs::path p = base / ("c2pool-analytics-" + tag + "-" + std::to_string(std::rand()));
        std::error_code ec;
        if (fs::create_directory(p, ec))
            return p;
    }
    ADD_FAILURE() << "no temp dir";
    return base;
}

void write_file(const fs::path& p, const std::string& text)
{
    std::ofstream f(p, std::ios::binary);
    f << text;
}

http::response<http::string_body> fetch(uint16_t port, const std::string& target)
{
    net::io_context ioc;
    tcp::socket sock(ioc);
    sock.connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port));
    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, "127.0.0.1");
    http::write(sock, req);
    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(sock, buffer, res);
    beast::error_code ec;
    sock.shutdown(tcp::socket::shutdown_both, ec);
    return res;
}

std::unique_ptr<core::WebServer> make_server(net::io_context& ioc, const fs::path& dir,
                                             const std::string& id)
{
    auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
    ws->set_stratum_port(0);
    ws->get_mining_interface()->set_dashboard_always_ready(true);
    ws->set_dashboard_dir(dir.string());
    ws->set_analytics_id(id);
    ws->start();
    return ws;
}

std::string quote_sh(const std::string& s)
{
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    return out + "'";
}

// A shell command's stdout and exit status.
struct ShellResult {
    std::string out;
    int status = -1;
};

ShellResult run_shell(const std::string& cmd)
{
    ShellResult r;
#ifndef _WIN32
    FILE* p = popen(cmd.c_str(), "r");
    if (!p)
        return r;
    char buf[4096];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, p)) > 0)
        r.out.append(buf, n);
    const int st = pclose(p);
    r.status = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
#endif
    return r;
}

bool have_python3()
{
#ifdef _WIN32
    return false;
#else
    return run_shell("python3 -I -B -c 'import sys; sys.exit(0)' 2>/dev/null").status == 0;
#endif
}

}  // namespace

// ── the helper ──────────────────────────────────────────────────────────────

TEST(AnalyticsTag, InjectsOnceBeforeHeadAndBannerBeforeBody)
{
    std::string html = kPage;
    ASSERT_TRUE(core::inject_analytics_tag(html, kId));

    const std::string head = core::analytics_head_snippet(kId, true);
    const std::string banner = core::analytics_consent_banner();
    EXPECT_EQ(count(html, head), 1u);
    EXPECT_EQ(count(html, banner), 1u);
    EXPECT_EQ(count(html, std::string(core::kAnalyticsMarker)), 1u);
    EXPECT_EQ(count(html, std::string(core::kAnalyticsConsentMarker)), 1u);
    EXPECT_EQ(count(html, "googletagmanager.com/gtag/js?id=" + kId), 1u);
    // Directly before </head> and </body>.
    EXPECT_NE(html.find(head + "</head>"), std::string::npos);
    EXPECT_NE(html.find(banner + "</body>"), std::string::npos);
    // The rest of the page is untouched.
    std::string back = html;
    back.erase(back.find(head), head.size());
    back.erase(back.find(banner), banner.size());
    EXPECT_EQ(back, kPage);

    // A second pass (or a page that already has it) changes nothing.
    const std::string once = html;
    EXPECT_FALSE(core::inject_analytics_tag(html, kId));
    EXPECT_EQ(html, once);
    EXPECT_FALSE(core::inject_analytics_tag(html, "G-OTHER999"));
    EXPECT_EQ(html, once);
}

TEST(AnalyticsTag, PageWithoutHeadIsUnchanged)
{
    for (const std::string page : {std::string("<p>fragment</p>"), std::string(""),
                                   std::string("<html><body>x</body></html>")}) {
        std::string html = page;
        EXPECT_FALSE(core::inject_analytics_tag(html, kId));
        EXPECT_EQ(html, page);
    }
}

TEST(AnalyticsTag, EmptyIdInjectsNothing)
{
    std::string html = kPage;
    EXPECT_FALSE(core::inject_analytics_tag(html, ""));
    EXPECT_EQ(html, kPage);
}

TEST(AnalyticsTag, PageWithoutBodyGetsHeadOnlyConsentDenied)
{
    const std::string page = "<html><head><title>t</title></head><p>no body close</p>";
    std::string html = page;
    ASSERT_TRUE(core::inject_analytics_tag(html, kId));
    EXPECT_EQ(count(html, core::analytics_head_snippet(kId, false)), 1u);
    EXPECT_EQ(html.find(std::string(core::kAnalyticsConsentMarker)), std::string::npos);
    // No stored-choice restore without the bar: consent stays denied.
    EXPECT_EQ(html.find("localStorage"), std::string::npos);
    EXPECT_EQ(html.find("'granted'"), std::string::npos);
    EXPECT_NE(html.find("gtag('consent','default'"), std::string::npos);
    EXPECT_EQ(html.find("c2poolGaStart();"), std::string::npos);   // nothing is ever sent
}

TEST(AnalyticsTag, UpperCaseTagsAndExistingGtag)
{
    std::string html = "<HTML><HEAD><TITLE>t</TITLE></HEAD><BODY>x</BODY></HTML>";
    ASSERT_TRUE(core::inject_analytics_tag(html, kId));
    EXPECT_NE(html.find(core::analytics_head_snippet(kId, true) + "</HEAD>"), std::string::npos);
    EXPECT_NE(html.find(core::analytics_consent_banner() + "</BODY>"), std::string::npos);

    // A page that loads gtag.js by itself is left alone (no double count).
    const std::string own =
        "<html><head><script async src=\"https://www.googletagmanager.com/gtag/js?id=G-OWN12345\">"
        "</script></head><body></body></html>";
    std::string h2 = own;
    EXPECT_FALSE(core::inject_analytics_tag(h2, kId));
    EXPECT_EQ(h2, own);
}

TEST(AnalyticsTag, ConsentDefaultDeniedBeforeConfig)
{
    for (bool restore : {true, false}) {
        const std::string s = core::analytics_head_snippet(kId, restore);
        const auto def = s.find(
            "gtag('consent','default',{analytics_storage:'denied',ad_storage:'denied',"
            "ad_user_data:'denied',ad_personalization:'denied'});");
        const auto loader = s.find("<script async src=\"https://www.googletagmanager.com/gtag/js?id=" + kId
                                   + "\" referrerpolicy=\"no-referrer\">");
        const auto config = s.find("gtag('config','" + kId + "',{send_page_view:false,");
        ASSERT_NE(def, std::string::npos);
        ASSERT_NE(loader, std::string::npos);
        ASSERT_NE(config, std::string::npos);
        EXPECT_LT(def, loader);
        EXPECT_LT(loader, config);
        EXPECT_EQ(count(s, "gtag('config'"), 1u);
        EXPECT_EQ(count(s, "gtag('event'"), 1u);
        // The config call and the page_view live only in the start function,
        // which runs once consent is granted.
        const auto start = s.find("function c2poolGaStart(){");
        ASSERT_NE(start, std::string::npos);
        EXPECT_LT(start, config);
        if (restore) {
            const std::string restore_call =
                "try{if(window.localStorage.getItem('c2pool_ga_consent')==='granted')"
                "{gtag('consent','update',{analytics_storage:'granted'});c2poolGaStart();}}catch(e){}";
            EXPECT_EQ(count(s, restore_call), 1u);
            EXPECT_EQ(count(s, "c2poolGaStart();"), 1u);   // the restore is the only call in <head>
        } else {
            EXPECT_EQ(s.find("c2poolGaStart();"), std::string::npos);   // never starts: no bar, no consent
        }
    }
}

TEST(AnalyticsTag, NoAdStorageTypeIsEverGranted)
{
    std::string all = core::analytics_head_snippet(kId, true) + core::analytics_head_snippet(kId, false)
                    + core::analytics_consent_banner();
    std::string page = kPage;
    core::inject_analytics_tag(page, kId);
    all += page;
    const std::regex ad_grant("ad_[a-z_]*\\s*:\\s*['\"]granted['\"]");
    EXPECT_FALSE(std::regex_search(all, ad_grant));
    // Every grant there is is analytics_storage alone.
    const std::regex any_grant("([a-z_]+)\\s*:\\s*'granted'");
    std::size_t grants = 0;
    for (auto it = std::sregex_iterator(all.begin(), all.end(), any_grant); it != std::sregex_iterator(); ++it) {
        EXPECT_EQ((*it)[1].str(), "analytics_storage");
        ++grants;
    }
    EXPECT_GT(grants, 0u);
    EXPECT_EQ(count(all, "{analytics_storage:'granted'}"), grants);
}

TEST(AnalyticsTag, BannerTextButtonsAndStorage)
{
    const std::string b = core::analytics_consent_banner();
    EXPECT_NE(b.find("This site uses Google Analytics cookies to count visits."), std::string::npos);
    EXPECT_NE(b.find(">Accept</button>"), std::string::npos);
    EXPECT_NE(b.find(">Decline</button>"), std::string::npos);
    // Every localStorage access is inside a try.
    EXPECT_EQ(count(b, "localStorage"), 2u);
    EXPECT_EQ(count(b, "try{v=window.localStorage.getItem(k);}catch(e){}"), 1u);
    EXPECT_EQ(count(b, "try{window.localStorage.setItem(k,c);}catch(e){}"), 1u);
    // Hidden until the script decides, removed on a stored choice.
    EXPECT_NE(b.find("style=\"display:none;position:fixed;"), std::string::npos);
    EXPECT_NE(b.find("if(v==='granted'||v==='denied'){bar.parentNode.removeChild(bar);return;}"),
              std::string::npos);
    // Dark text on a light bar; no external resource.
    EXPECT_NE(b.find("background:#f5f5f5;color:#111;"), std::string::npos);
    EXPECT_EQ(b.find("src="), std::string::npos);
    EXPECT_EQ(b.find("http"), std::string::npos);
}

TEST(AnalyticsTag, IdValidation)
{
    for (const char* ok : {"G-TEST1234", "G-ABCD", "G-ABCDEFGHIJ0123456789", "UA-12345678-1",
                           "UA-1234-1234"})
        EXPECT_TRUE(core::is_valid_analytics_id(ok)) << ok;
    for (const char* bad : {"", "G-", "G-ABC", "G-ABCDEFGHIJ01234567890", "g-abcd1234", "G-abcd1234",
                            "G-ABCD1234\n", " G-ABCD1234", "G-ABCD 1234", "G-ABCD'+alert(1)+'",
                            "G-ABCD\"><script>", "G-ABCD</script>", "UA-123-1", "UA-12345678",
                            "UA-12345678-", "UA-12345678-12345", "UA-ABCDEFGH-1", "GTM-ABCD123",
                            "AW-123456789", "G-ABCD1234&x=1"})
        EXPECT_FALSE(core::is_valid_analytics_id(bad)) << bad;

    // Command line: refused, the value in force is kept.
    std::string id = "G-KEEP1234";
    EXPECT_FALSE(core::parse_analytics_id("G-bad'", id));
    EXPECT_EQ(id, "G-KEEP1234");
    EXPECT_TRUE(core::parse_analytics_id("", id));   // explicit off
    EXPECT_EQ(id, "");
    EXPECT_TRUE(core::parse_analytics_id(kId, id));
    EXPECT_EQ(id, kId);

    // Settings file: warned about and ignored.
    std::string file_id = kId;
    EXPECT_FALSE(core::apply_analytics_id_setting("web.analytics_id", "<script>", file_id));
    EXPECT_EQ(file_id, kId);
    EXPECT_TRUE(core::apply_analytics_id_setting("web.analytics_id", "G-FILE1234", file_id));
    EXPECT_EQ(file_id, "G-FILE1234");

    // The helper itself never emits an unvalidated ID.
    for (const char* bad : {"G-ABCD'+alert(1)+'", "x", "G-ABCD\"><script>"}) {
        std::string html = kPage;
        EXPECT_FALSE(core::inject_analytics_tag(html, bad));
        EXPECT_EQ(html, kPage);
    }
}

// ── the settings layers ────────────────────────────────────────────────────

TEST(AnalyticsTag, CatalogRowForEveryBinaryDefaultOff)
{
    using namespace c2pool::catalog;
    const ParamRow* row = find_by_canon("web.analytics_id");
    ASSERT_NE(row, nullptr);
    EXPECT_EQ(row->default_literal, "");
    EXPECT_FALSE(row->is_money());
    for (Bin b : {Bin::BIN_DASH, Bin::BIN_LTC, Bin::BIN_BTC, Bin::BIN_DGB, Bin::BIN_BCH, Bin::BIN_BIP110}) {
        const ParamRow* r = find_by_alias(b, "--analytics-id");
        ASSERT_NE(r, nullptr) << bin_name(b);
        EXPECT_EQ(r->canon, "web.analytics_id") << bin_name(b);
    }
    for (CoinBit c : {C_DASH, C_LTC, C_BTC, C_DGB, C_BCH, C_BIP110}) {
        EXPECT_TRUE(row->applies_to(c));
        c2pool::settings::ResolvedConfig rc;
        rc.seed_compiled_defaults(c);
        // Not set by anything: the compiled default "" (off), not in the dump.
        EXPECT_FALSE(rc.has("web.analytics_id"));
        EXPECT_FALSE(rc.file_set("web.analytics_id"));
    }
}

TEST(AnalyticsTag, CommandLineWinsOverSettingsFile)
{
    namespace cs = c2pool::settings;
    using namespace c2pool::catalog;
    const fs::path dir = make_temp_dir("toml");
    const fs::path toml = dir / "c2pool.toml";
    write_file(toml, "[dash.web]\nanalytics_id = \"G-FILE1234\"\n");

    auto resolve = [&](std::vector<std::string> args) {
        std::vector<std::string> store{"c2pool-dash"};
        for (auto& a : args) store.push_back(a);
        std::vector<char*> argv;
        for (auto& s : store) argv.push_back(s.data());
        cs::ResolvedConfig rc;
        rc.seed_compiled_defaults(C_DASH);
        cs::CliTracker tr;
        cs::scan_cli(static_cast<int>(argv.size()), argv.data(), Bin::BIN_DASH, tr, rc);
        EXPECT_EQ(cs::wire_settings(toml.string(), C_DASH, tr, rc), 0);
        return rc;
    };
    {
        const auto rc = resolve({});
        EXPECT_TRUE(rc.file_set("web.analytics_id"));
        EXPECT_EQ(rc.get_string("web.analytics_id").value_or(""), "G-FILE1234");
    }
    {
        const auto rc = resolve({"--analytics-id", "G-CLI12345"});
        EXPECT_FALSE(rc.file_set("web.analytics_id"));
        EXPECT_TRUE(rc.source_of("web.analytics_id") == cs::Source::Cli);
        EXPECT_EQ(rc.get_string("web.analytics_id").value_or(""), "G-CLI12345");
    }
    // A bad file value loads (the node starts) and is then ignored.
    write_file(toml, "[dash.web]\nanalytics_id = \"G-ABCD'+x+'\"\n");
    {
        const auto rc = resolve({});
        ASSERT_TRUE(rc.file_set("web.analytics_id"));
        std::string id;
        EXPECT_FALSE(core::apply_analytics_id_setting(
            "web.analytics_id", rc.get_string("web.analytics_id").value_or(""), id));
        EXPECT_EQ(id, "");
    }
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ── a real web server ──────────────────────────────────────────────────────

TEST(AnalyticsTag, WebServerTagsStaticHtmlOnly)
{
    const fs::path dir = make_temp_dir("web");
    write_file(dir / "dashboard.html", kPage);
    write_file(dir / "page.htm", kPage);
    write_file(dir / "app.js", "var s='</head></body>';\n");
    write_file(dir / "frag.html", "<p>no head</p>");

    {
        net::io_context ioc;
        auto ws = make_server(ioc, dir, kId);
        const uint16_t port = ws->bound_port();
        for (const char* target : {"/", "/dashboard.html", "/page.htm"}) {
            const auto res = fetch(port, target);
            EXPECT_EQ(res.result_int(), 200) << target;
            EXPECT_EQ(count(res.body(), core::analytics_head_snippet(kId, true)), 1u) << target;
            EXPECT_EQ(count(res.body(), core::analytics_consent_banner()), 1u) << target;
        }
        // Every request reads the file again: still exactly once.
        EXPECT_EQ(count(fetch(port, "/dashboard.html").body(), std::string(core::kAnalyticsMarker)), 1u);
        EXPECT_EQ(fetch(port, "/app.js").body(), "var s='</head></body>';\n");
        EXPECT_EQ(fetch(port, "/frag.html").body(), "<p>no head</p>");
        ws->stop();
    }
    {
        net::io_context ioc;
        auto ws = make_server(ioc, dir, "");   // default: off
        EXPECT_EQ(fetch(ws->bound_port(), "/dashboard.html").body(), kPage);
        ws->stop();
    }
    {
        net::io_context ioc;
        auto ws = make_server(ioc, dir, "G-ABCD'+x+'");   // never served
        EXPECT_EQ(ws->get_mining_interface()->get_analytics_id(), "");
        EXPECT_EQ(fetch(ws->bound_port(), "/dashboard.html").body(), kPage);
        ws->stop();
    }
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ── every coin binary: flag -> setting -> web server (source wiring) ───────

TEST(AnalyticsTag, EveryBinaryWiresTheFlagIntoItsWebServer)
{
    struct Lane {
        const char* main;        // the parse + settings overlay
        const char* flag;        // the CLI branch
        const char* parse;       // the parse writes ...
        const char* file;        // ... the settings file overlay writes (nullptr: no settings file)
        const char* web;         // the web server standup reads it
        const char* wire;
    };
    const Lane lanes[] = {
        {"c2pool/main_ltc.cpp", "arg == \"--analytics-id\"",
         "core::parse_analytics_id(argv[++i], analytics_id)",
         "core::apply_analytics_id_setting(\"web.analytics_id\", rc.get_string(\"web.analytics_id\").value_or(\"\"), analytics_id);",
         "c2pool/main_ltc.cpp", "web_server.set_analytics_id(analytics_id);"},
        {"c2pool/main_dash.cpp", "std::strcmp(argv[i], \"--analytics-id\") == 0",
         "core::parse_analytics_id(argv[++i], core::analytics_id_setting())",
         "core::apply_analytics_id_setting(\"web.analytics_id\", rc.get_string(\"web.analytics_id\").value_or(\"\"), core::analytics_id_setting());",
         "c2pool/main_dash.cpp", "web_server->set_analytics_id(core::analytics_id_setting());"},
        {"c2pool/main_btc.cpp", "arg == \"--analytics-id\"",
         "core::parse_analytics_id(argv[++i], core::analytics_id_setting())",
         "core::apply_analytics_id_setting(\"web.analytics_id\", rc.get_string(\"web.analytics_id\").value_or(\"\"), core::analytics_id_setting());",
         "c2pool/main_btc.cpp", "web_server->set_analytics_id(core::analytics_id_setting());"},
        {"c2pool/main_bch.cpp", "std::strcmp(argv[i], \"--analytics-id\") == 0",
         "core::parse_analytics_id(argv[++i], core::analytics_id_setting())",
         "core::apply_analytics_id_setting(\"web.analytics_id\", rc.get_string(\"web.analytics_id\").value_or(\"\"), core::analytics_id_setting());",
         "impl/bch/pool_entrypoint.hpp", "web_server->set_analytics_id(core::analytics_id_setting());"},
        {"c2pool/main_dgb.cpp", "std::strcmp(argv[i], \"--analytics-id\") == 0",
         "core::parse_analytics_id(argv[++i], core::analytics_id_setting())",
         "core::apply_analytics_id_setting(\"web.analytics_id\", rc.get_string(\"web.analytics_id\").value_or(\"\"), core::analytics_id_setting());",
         "c2pool/main_dgb.cpp", "web_server->set_analytics_id(core::analytics_id_setting());"},
        {"c2pool/main_bip110.cpp", "arg == \"--analytics-id\"",
         "core::parse_analytics_id(argv[++i], core::analytics_id_setting())",
         nullptr,   // c2pool-bip110 reads no settings file
         "c2pool/main_bip110.cpp", "web_server->set_analytics_id(core::analytics_id_setting());"},
    };
    for (const auto& l : lanes) {
        const std::string m = src(l.main);
        const auto flag = m.find(l.flag);
        ASSERT_NE(flag, std::string::npos) << l.main << ": " << l.flag;
        // The value is checked right in the flag's branch, and a bad one refused.
        const auto parse = m.find(l.parse, flag);
        ASSERT_NE(parse, std::string::npos) << l.main << ": " << l.parse;
        EXPECT_LT(parse - flag, 160u) << l.main;
        const auto refuse = m.find("return ", parse);
        ASSERT_NE(refuse, std::string::npos);
        EXPECT_LT(refuse - parse, 260u) << l.main << ": bad --analytics-id must refuse the start";
        EXPECT_NE(m.find("--analytics-id ID"), std::string::npos) << l.main << ": --help text";
        // The --help text says it plainly: off by default, a consent bar, GA4
        // page views only after consent, stripped, the operator's privacy notice.
        for (const char* phrase : {"off by default", "consent bar", "GA4", "page views",
                                   "addresses and query", "privacy notice"})
            EXPECT_NE(m.find(phrase), std::string::npos) << l.main << ": --help lacks '" << phrase << "'";
        if (l.file) {
            EXPECT_NE(m.find(std::string("if (rc.file_set(\"web.analytics_id\")) // --analytics-id: a bad value is warned about and ignored ") + l.file),
                      std::string::npos) << l.main << ": settings-file overlay";
        }
        // Wired right after the dashboard dir of the one web server that serves it.
        const std::string w = src(l.web);
        const auto dash = w.find("set_dashboard_dir(");
        ASSERT_NE(dash, std::string::npos) << l.web;
        EXPECT_EQ(w.find("set_dashboard_dir(", dash + 1), std::string::npos) << l.web << ": one dashboard";
        const auto wire = w.find(l.wire, dash);
        ASSERT_NE(wire, std::string::npos) << l.web << ": " << l.wire;
        EXPECT_LT(wire - dash, 200u) << l.web;
    }
    // c2pool-ltc's legacy YAML key takes the same check as the settings file.
    EXPECT_NE(src("c2pool/main_ltc.cpp").find(
                  "core::apply_analytics_id_setting(\"analytics_id\", cfg[\"analytics_id\"].as<std::string>(), analytics_id);"),
              std::string::npos);
    // The static path uses the one helper; no other gtag text in the server.
    const std::string session = src("core/http_session.cpp");
    EXPECT_NE(session.find("if ((ext == \".html\" || ext == \".htm\") && core::analytics_allowed_target(target, tag_query)) "
                           "core::inject_analytics_tag(contents, mining_interface_->get_analytics_id());"),
              std::string::npos);
    EXPECT_EQ(session.find("googletagmanager"), std::string::npos);
}

// ── privacy ────────────────────────────────────────────────────────────────

TEST(AnalyticsTag, NeverOnControlAdminApiLogsOrTokenRequests)
{
    for (const char* path : {"/control/page.html", "/control", "/api/admin/page.html", "/api/admin/pool/x.html",
                             "/api/config", "/api/page.html", "/api", "/web/log", "/logs/export", "/logs/x.html"})
        EXPECT_FALSE(core::analytics_allowed_target(path, "")) << path;
    for (const char* query : {"token=s3cret", "a=1&token=s3cret", "control_token=x", "TOKEN", "auth_token=1&b=2"})
        EXPECT_FALSE(core::analytics_allowed_target("/dashboard.html", query)) << query;
    for (const char* path : {"/", "/dashboard.html", "/miner.html", "/sharechain-explorer/pplns-embed.html",
                             "/controls.html", "/apix.html", "/web/logo.html"})
        EXPECT_TRUE(core::analytics_allowed_target(path, "")) << path;
    EXPECT_TRUE(core::analytics_allowed_target("/miner.html", "address=LVypG8dmR2bcvq5zQ7wDk3HJ9nXyZ1aBcD"));
}

TEST(AnalyticsTag, WebServerNoTagOnGatedPathsTokenOrNonHtml)
{
    const fs::path dir = make_temp_dir("gated");
    write_file(dir / "dashboard.html", kPage);
    fs::create_directories(dir / "control");
    fs::create_directories(dir / "api" / "admin");
    fs::create_directories(dir / "api" / "config");
    fs::create_directories(dir / "logs");
    for (const fs::path& p : {dir / "control" / "page.html", dir / "api" / "admin" / "page.html",
                              dir / "api" / "config" / "page.html", dir / "api" / "page.html",
                              dir / "logs" / "page.html"})
        write_file(p, kPage);
    for (const char* f : {"data.json", "notes.txt", "app.js", "style.css", "pic.svg"})
        write_file(dir / f, kPage);   // HTML text in a non-HTML file

    {
        net::io_context ioc;
        auto ws = make_server(ioc, dir, kId);
        const uint16_t port = ws->bound_port();
        // The public page does get it (the same server, the same ID).
        EXPECT_EQ(count(fetch(port, "/dashboard.html").body(), std::string(core::kAnalyticsMarker)), 1u);
        for (const char* target : {"/control/page.html", "/api/admin/page.html", "/api/config/page.html",
                                   "/api/page.html", "/logs/page.html", "/dashboard.html?token=x",
                                   "/data.json", "/notes.txt", "/app.js", "/style.css", "/pic.svg"}) {
            const auto res = fetch(port, target);
            EXPECT_EQ(res.result_int(), 200) << target;   // served, so the page did reach the injector
            EXPECT_EQ(res.body(), kPage) << target;
        }
        ws->stop();
    }
    {
        // Behind the auth token: /control/* needs ?token=, and that page gets no tag.
        net::io_context ioc;
        auto ws = std::make_unique<core::WebServer>(ioc, "127.0.0.1", 0, false);
        ws->set_stratum_port(0);
        ws->get_mining_interface()->set_dashboard_always_ready(true);
        ws->get_mining_interface()->set_auth_token("s3cret-token");
        ws->set_dashboard_dir(dir.string());
        ws->set_analytics_id(kId);
        ws->start();
        const uint16_t port = ws->bound_port();
        EXPECT_EQ(fetch(port, "/control/page.html").result_int(), 401);
        const auto res = fetch(port, "/control/page.html?token=s3cret-token");
        EXPECT_EQ(res.result_int(), 200);
        EXPECT_EQ(res.body(), kPage);
        EXPECT_EQ(fetch(port, "/dashboard.html?token=s3cret-token").body(), kPage);
        ws->stop();
    }
    std::error_code ec;
    fs::remove_all(dir, ec);
}

const std::string kAddr = "LVypG8dmR2bcvq5zQ7wDk3HJ9nXyZ1aBcD";

TEST(AnalyticsTag, SanitizePathDropsQueryAndAddresses)
{
    struct V { std::string in, out; };
    const std::vector<V> v = {
        {"/miner_payouts/" + kAddr, "/miner_payouts/:addr"},
        {"/miner.html?address=" + kAddr, "/miner.html"},
        {"/merged_miner_payouts/D" + kAddr, "/merged_miner_payouts/:addr"},
        {"/miner_stats/" + kAddr + ".rig1", "/miner_stats/:addr"},
        {"/miner_stats/bob", "/miner_stats/:addr"},          // after a per-miner route: whatever it is
        {"/pplns/miner/" + kAddr, "/pplns/miner/:addr"},
        {"/web/payout_address/" + kAddr, "/web/payout_address/:addr"},
        {"/patron_sendmany/0.5", "/patron_sendmany/:addr"},
        {"/x/bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "/x/:addr"},
        {"/x/bitcoincash%3Aqpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "/x/:addr"},
        {"/x/ltc1qg82tbd6sv7sdyqk8zfgm9frf7y0lv0rkx8dpnu/y", "/x/:addr/:addr"},
        {"/dashboard.html?user=" + kAddr + "&worker=rig1#share", "/dashboard.html"},
        {"/share.html#" + kAddr, "/share.html"},
        {"/", "/"},
        {"", "/"},
        {"/dashboard.html", "/dashboard.html"},
        {"/sharechain-explorer/pplns-embed.html", "/sharechain-explorer/pplns-embed.html"},
        {"/miners.html", "/miners.html"},
        {"/ab:short", "/ab:short"},
        {"/abc1:" + kAddr, "/:addr"},
        {"/0123456789abcdefghi", "/0123456789abcdefghi"},   // 19: kept
        {"/0123456789abcdefghij", "/:addr"},                // 20: replaced
    };
    for (const auto& x : v) {
        EXPECT_EQ(core::analytics_sanitize_path(x.in), x.out) << x.in;
        EXPECT_EQ(core::analytics_sanitize_path(x.in).find(kAddr), std::string::npos) << x.in;
    }
}

TEST(AnalyticsTag, SnippetSendsOnlySanitizedPageViewsAfterConsent)
{
    const std::string all = core::analytics_head_snippet(kId, true) + core::analytics_consent_banner();
    // GA never sees the raw URL: no location.href / location.search / hash use,
    // the referrer only through the same sanitizer, explicit page fields.
    EXPECT_EQ(all.find("location.href"), std::string::npos);
    EXPECT_EQ(all.find("location.search"), std::string::npos);
    EXPECT_EQ(all.find("location.hash"), std::string::npos);
    EXPECT_EQ(count(all, "document.referrer"), 2u);
    EXPECT_NE(all.find("r=u.origin+c2poolGaPath(u.pathname);"), std::string::npos);
    EXPECT_NE(all.find("var p=c2poolGaPath(location.pathname),r='';"), std::string::npos);
    EXPECT_NE(all.find(std::string(core::kAnalyticsPathJs)), std::string::npos);
    EXPECT_NE(all.find("gtag('config','" + kId + "',{send_page_view:false,page_location:v.page_location,"
                       "page_path:p,page_referrer:r,page_title:t});"), std::string::npos);
    EXPECT_NE(all.find("gtag('event','page_view',v);"), std::string::npos);
    EXPECT_NE(all.find("var v={page_location:location.origin+p,page_path:p,page_referrer:r,page_title:t};"),
              std::string::npos);
    // No request from the page carries its URL as a referrer.
    EXPECT_NE(all.find("<meta name=\"referrer\" content=\"no-referrer\">"), std::string::npos);
    EXPECT_NE(all.find("referrerpolicy=\"no-referrer\""), std::string::npos);
    // Accept starts it; nothing else does.
    EXPECT_NE(all.find("if(typeof c2poolGaStart==='function'){c2poolGaStart();}"), std::string::npos);
    EXPECT_EQ(count(all, "c2poolGaStart();"), 2u);   // the restore and Accept
}

namespace {

bool have_node()
{
#ifdef _WIN32
    return false;
#else
    return run_shell("node -e 'process.exit(0)' 2>/dev/null").status == 0;
#endif
}

// Runs every inline <script> of a page in one node vm context with a fake
// location / document / localStorage and the consent bar, optionally clicks
// a button, and prints the dataLayer (one JSON line per phase).
const char* kNodeHarness = R"JS(
const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync(process.argv[2], 'utf8');
const sc = JSON.parse(process.argv[3]);
const scripts = [];
const re = /<script>([\s\S]*?)<\/script>/g;
let m;
while ((m = re.exec(html)) !== null) scripts.push(m[1]);
function el(attrs) { return { style: {}, attrs: attrs || {}, getAttribute(k) { return this.attrs[k]; }, parentNode: null }; }
const body = { removeChild(c) { c.parentNode = null; }, insertBefore(n) { n.parentNode = body; } };
const accept = el({ 'data-c2pool-ga': 'granted' }), decline = el({ 'data-c2pool-ga': 'denied' });
const bar = el(); bar.parentNode = body; bar.offsetHeight = 40;
bar.getElementsByTagName = () => [accept, decline];
const store = {};
if (sc.stored) store.c2pool_ga_consent = sc.stored;
const ctx = {
  location: { origin: 'https://pool.example', pathname: sc.pathname, search: sc.search, hash: '#frag',
              href: 'https://pool.example' + sc.pathname + sc.search + '#frag' },
  document: { referrer: sc.referrer, title: sc.title,
              getElementById: (id) => (id === 'c2pool-ga-consent' ? bar : null),
              createElement: () => el() },
  localStorage: { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
  URL, Date, String,
};
ctx.window = ctx;
vm.createContext(ctx);
for (const s of scripts) vm.runInContext(s, ctx);
const dump = (phase) => console.log(JSON.stringify({ phase, dataLayer: (ctx.dataLayer || []).map((a) => Array.from(a)),
  bar: bar.style.display || '', barRemoved: bar.parentNode === null, stored: store.c2pool_ga_consent || null }));
dump('load');
if (sc.click === 'accept') { accept.onclick(); dump('click'); }
if (sc.click === 'decline') { decline.onclick(); dump('click'); }
if (sc.paths) console.log(JSON.stringify({ phase: 'paths', out: sc.paths.map((p) => ctx.c2poolGaPath(p)) }));
)JS";

// The dataLayer commands of one phase, by name ("consent", "config", ...).
std::vector<nlohmann::json> commands(const nlohmann::json& phase, const std::string& name)
{
    std::vector<nlohmann::json> out;
    for (const auto& c : phase["dataLayer"])
        if (c.is_array() && !c.empty() && c[0] == name)
            out.push_back(c);
    return out;
}

}  // namespace

TEST(AnalyticsTag, SnippetUnderNodeSendsNoAddressAndNothingBeforeConsent)
{
    if (!have_node())
        GTEST_SKIP() << "node not installed";
    const fs::path dir = make_temp_dir("node");
    const fs::path harness = dir / "harness.js";
    write_file(harness, kNodeHarness);
    std::string page = kPage;
    ASSERT_TRUE(core::inject_analytics_tag(page, kId));
    const fs::path html = dir / "page.html";
    write_file(html, page);

    auto run_page = [&](const nlohmann::json& sc) {
        const ShellResult r = run_shell("node " + quote_sh(harness.string()) + " " + quote_sh(html.string()) + " "
                                        + quote_sh(sc.dump()) + " 2>&1");
        EXPECT_EQ(r.status, 0) << r.out;
        // Nothing the harness saw (all that would go to gtag) holds the address.
        EXPECT_EQ(r.out.find(kAddr), std::string::npos) << r.out;
        EXPECT_EQ(r.out.find("rig1"), std::string::npos) << r.out;
        EXPECT_EQ(r.out.find("frag"), std::string::npos) << r.out;
        std::vector<nlohmann::json> phases;
        std::istringstream lines(r.out);
        for (std::string line; std::getline(lines, line);)
            if (!line.empty())
                phases.push_back(nlohmann::json::parse(line, nullptr, false));
        return phases;
    };
    const std::string title = "Miner " + kAddr;

    // A returning visitor who accepted: one sanitized page view, nothing raw.
    {
        const auto ph = run_page({{"pathname", "/miner_payouts/" + kAddr},
                                  {"search", "?address=" + kAddr + "&worker=rig1"},
                                  {"referrer", "https://ref.example/miner.html?address=" + kAddr},
                                  {"title", title}, {"stored", "granted"}});
        ASSERT_GE(ph.size(), 1u);
        const auto consent = commands(ph[0], "consent");
        ASSERT_EQ(consent.size(), 2u);
        EXPECT_EQ(consent[0][1], "default");
        for (const char* k : {"analytics_storage", "ad_storage", "ad_user_data", "ad_personalization"})
            EXPECT_EQ(consent[0][2][k], "denied") << k;
        EXPECT_EQ(consent[1][1], "update");
        EXPECT_EQ(consent[1][2].dump(), R"({"analytics_storage":"granted"})");
        const auto config = commands(ph[0], "config");
        ASSERT_EQ(config.size(), 1u);
        EXPECT_EQ(config[0][1], kId);
        EXPECT_EQ(config[0][2]["send_page_view"], false);
        EXPECT_EQ(config[0][2]["page_location"], "https://pool.example/miner_payouts/:addr");
        EXPECT_EQ(config[0][2]["page_path"], "/miner_payouts/:addr");
        EXPECT_EQ(config[0][2]["page_referrer"], "https://ref.example/miner.html");
        EXPECT_EQ(config[0][2]["page_title"], "Miner :addr");
        const auto events = commands(ph[0], "event");
        ASSERT_EQ(events.size(), 1u);
        EXPECT_EQ(events[0][1], "page_view");
        EXPECT_EQ(events[0][2]["page_location"], "https://pool.example/miner_payouts/:addr");
        EXPECT_EQ(ph[0]["barRemoved"], true);
        // Default denied comes first, the config only after the grant.
        const auto& dl = ph[0]["dataLayer"];
        std::size_t i_default = 99, i_update = 99, i_config = 99;
        for (std::size_t i = 0; i < dl.size(); ++i) {
            if (dl[i][0] == "consent" && dl[i][1] == "default") i_default = i;
            if (dl[i][0] == "consent" && dl[i][1] == "update") i_update = i;
            if (dl[i][0] == "config") i_config = i;
        }
        EXPECT_LT(i_default, i_update);
        EXPECT_LT(i_update, i_config);
    }
    // A first visit: nothing is sent until Accept; Accept sends one clean page view.
    {
        const auto ph = run_page({{"pathname", "/miner.html"}, {"search", "?address=" + kAddr},
                                  {"referrer", ""}, {"title", "Miner Stats - c2pool"}, {"click", "accept"}});
        ASSERT_EQ(ph.size(), 2u);
        EXPECT_EQ(ph[0]["bar"], "flex");
        EXPECT_TRUE(commands(ph[0], "config").empty());
        EXPECT_TRUE(commands(ph[0], "event").empty());
        EXPECT_EQ(commands(ph[0], "consent").size(), 1u);
        const auto config = commands(ph[1], "config");
        ASSERT_EQ(config.size(), 1u);
        EXPECT_EQ(config[0][2]["page_location"], "https://pool.example/miner.html");
        EXPECT_EQ(config[0][2]["page_path"], "/miner.html");
        EXPECT_EQ(commands(ph[1], "event").size(), 1u);
        EXPECT_EQ(ph[1]["stored"], "granted");
        EXPECT_EQ(ph[1]["barRemoved"], true);
    }
    // Decline, or a stored decline: nothing is ever sent.
    for (const nlohmann::json& sc : {nlohmann::json{{"pathname", "/miner.html"}, {"search", "?address=" + kAddr},
                                                    {"referrer", ""}, {"title", "t"}, {"click", "decline"}},
                                     nlohmann::json{{"pathname", "/miner.html"}, {"search", "?address=" + kAddr},
                                                    {"referrer", ""}, {"title", "t"}, {"stored", "denied"}}}) {
        const auto ph = run_page(sc);
        ASSERT_FALSE(ph.empty());
        for (const auto& p : ph) {
            EXPECT_TRUE(commands(p, "config").empty()) << sc.dump();
            EXPECT_TRUE(commands(p, "event").empty()) << sc.dump();
            for (const auto& c : commands(p, "consent"))
                EXPECT_NE(c[1], "update") << sc.dump();
        }
        EXPECT_EQ(ph.back()["barRemoved"], true);
    }
    // The script's sanitizer and its C++ port agree.
    {
        const std::vector<std::string> paths = {
            "/miner_payouts/" + kAddr, "/miner.html", "/", "", "/merged_miner_payouts/D" + kAddr,
            "/miner_stats/" + kAddr + ".rig1", "/miner_stats/bob", "/pplns/miner/" + kAddr,
            "/x/bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            "/x/bitcoincash%3Aqpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            "/x/ltc1qg82tbd6sv7sdyqk8zfgm9frf7y0lv0rkx8dpnu/y", "/dashboard.html",
            "/sharechain-explorer/pplns-embed.html", "/ab:short", "/a/b/c", "//double", "/abc1:" + kAddr};
        const ShellResult r = run_shell("node " + quote_sh(harness.string()) + " " + quote_sh(html.string()) + " "
                                        + quote_sh(nlohmann::json{{"pathname", "/"}, {"search", ""}, {"referrer", ""},
                                                                  {"title", "t"}, {"paths", paths}}.dump()));
        ASSERT_EQ(r.status, 0) << r.out;
        nlohmann::json last;
        std::istringstream lines(r.out);
        for (std::string line; std::getline(lines, line);)
            if (!line.empty())
                last = nlohmann::json::parse(line, nullptr, false);
        ASSERT_EQ(last["phase"], "paths");
        ASSERT_EQ(last["out"].size(), paths.size());
        for (std::size_t i = 0; i < paths.size(); ++i)
            EXPECT_EQ(last["out"][i].get<std::string>(), core::analytics_sanitize_path(paths[i])) << paths[i];
        EXPECT_EQ(last["out"][0], "/miner_payouts/:addr");
    }
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ── explorer/explorer.py: the generated pages ──────────────────────────────

TEST(AnalyticsTag, ExplorerGeneratedPageCarriesTheSameTag)
{
    if (!have_python3())
        GTEST_SKIP() << "python3 not installed";
    const fs::path explorer_dir = fs::path(C2POOL_SRC_ROOT) / ".." / "explorer";
    ASSERT_TRUE(fs::exists(explorer_dir / "explorer.py"));

    // Drives ExplorerHandler.do_GET on a fake engine (no coin node, no socket)
    // and prints the raw HTTP response. -B: no __pycache__ in the source tree.
    const fs::path dir = make_temp_dir("py");
    const fs::path script = dir / "explorer_page.py";
    write_file(script,
        "import io, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "import explorer\n"
        "explorer.ANALYTICS_ID = sys.argv[2]\n"
        "class Engine:\n"
        "    coins = ['ltc']\n"
        "    primary = 'ltc'\n"
        "    def coin_or_primary(self, c): return 'ltc'\n"
        "    def chain_label(self, c): return 'Litecoin'\n"
        "    def footer_label(self): return 'Litecoin Explorer'\n"
        "explorer.ExplorerHandler.engine = Engine()\n"
        "h = explorer.ExplorerHandler.__new__(explorer.ExplorerHandler)\n"
        "h.path = sys.argv[3]\n"
        "h.request_version = 'HTTP/1.1'\n"
        "h.requestline = 'GET ' + sys.argv[3] + ' HTTP/1.1'\n"
        "h.command = 'GET'\n"
        "h.client_address = ('127.0.0.1', 0)\n"
        "h.close_connection = True\n"
        "h.wfile = io.BytesIO()\n"
        "h.do_GET()\n"
        "sys.stdout.write(h.wfile.getvalue().decode())\n");
    auto page = [&](const std::string& id, const std::string& target) {
        return run_shell("python3 -I -B " + quote_sh(script.string()) + " " + quote_sh(explorer_dir.string()) + " "
                   + quote_sh(id) + " " + quote_sh(target) + " 2>/dev/null");
    };

    const ShellResult tagged = page(kId, "/no-such-page");
    ASSERT_EQ(tagged.status, 0) << tagged.out;
    ASSERT_NE(tagged.out.find("Content-Type: text/html"), std::string::npos) << tagged.out;
    ASSERT_NE(tagged.out.find("<title>404</title>"), std::string::npos);
    // Byte-identical to the node's own tag, once each, in place.
    EXPECT_EQ(count(tagged.out, core::analytics_head_snippet(kId, true) + "</head>"), 1u);
    EXPECT_EQ(count(tagged.out, core::analytics_consent_banner() + "</body>"), 1u);
    EXPECT_EQ(count(tagged.out, std::string(core::kAnalyticsMarker)), 1u);

    const ShellResult off = page("", "/no-such-page");
    ASSERT_EQ(off.status, 0);
    EXPECT_EQ(off.out.find("c2pool-analytics"), std::string::npos);
    EXPECT_EQ(off.out.find("gtag"), std::string::npos);

    // Its own defensive check: an ID set around the flag check is not emitted.
    const ShellResult bad = page("G-ABCD'+x+'", "/no-such-page");
    ASSERT_EQ(bad.status, 0);
    EXPECT_EQ(bad.out.find("gtag"), std::string::npos);

    // The same page builder, both ways (the helper alone).
    const ShellResult same = run_shell("python3 -I -B -c " + quote_sh(
        "import sys; sys.path.insert(0, sys.argv[1]); import explorer as e; "
        "sys.stdout.write(e.inject_analytics_tag(sys.argv[2], sys.argv[3]))")
        + " " + quote_sh(explorer_dir.string()) + " " + quote_sh(kPage) + " " + quote_sh(kId));
    std::string cpp = kPage;
    core::inject_analytics_tag(cpp, kId);
    EXPECT_EQ(same.out, cpp);
    const std::string nobody = "<html><head></head><p>x</p>";
    const ShellResult same2 = run_shell("python3 -I -B -c " + quote_sh(
        "import sys; sys.path.insert(0, sys.argv[1]); import explorer as e; "
        "sys.stdout.write(e.inject_analytics_tag(sys.argv[2], sys.argv[3]))")
        + " " + quote_sh(explorer_dir.string()) + " " + quote_sh(nobody) + " " + quote_sh(kId));
    std::string cpp2 = nobody;
    core::inject_analytics_tag(cpp2, kId);
    EXPECT_EQ(same2.out, cpp2);

    // --analytics-id with a bad value: refused before anything starts.
    const ShellResult refused = run_shell("python3 -I -B " + quote_sh((explorer_dir / "explorer.py").string())
                            + " --analytics-id " + quote_sh("G-ABCD'+x+'") + " 2>&1");
    EXPECT_NE(refused.status, 0);
    EXPECT_NE(refused.out.find("bad value: --analytics-id"), std::string::npos) << refused.out;

    std::error_code ec;
    fs::remove_all(dir, ec);
}
