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
    return run_shell("python3 -I -c 'import sys; sys.exit(0)' 2>/dev/null").status == 0;
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
        const auto loader = s.find("<script async src=\"https://www.googletagmanager.com/gtag/js?id=" + kId + "\">");
        const auto config = s.find("gtag('config','" + kId + "');");
        ASSERT_NE(def, std::string::npos);
        ASSERT_NE(loader, std::string::npos);
        ASSERT_NE(config, std::string::npos);
        EXPECT_LT(def, loader);
        EXPECT_LT(loader, config);
        EXPECT_EQ(count(s, "gtag('config'"), 1u);
        if (restore) {
            const auto upd = s.find("gtag('consent','update',{analytics_storage:'granted'})");
            ASSERT_NE(upd, std::string::npos);
            EXPECT_LT(def, upd);
            EXPECT_LT(upd, config);   // a returning visitor's page_view is counted with consent
            EXPECT_NE(s.find("try{if(window.localStorage.getItem('c2pool_ga_consent')==='granted')"),
                      std::string::npos);
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
    EXPECT_NE(session.find("core::inject_analytics_tag(contents, mining_interface_->get_analytics_id());"),
              std::string::npos);
    EXPECT_EQ(session.find("googletagmanager"), std::string::npos);
}

// ── explorer/explorer.py: the generated pages ──────────────────────────────

TEST(AnalyticsTag, ExplorerGeneratedPageCarriesTheSameTag)
{
    if (!have_python3())
        GTEST_SKIP() << "python3 not installed";
    const fs::path explorer_dir = fs::path(C2POOL_SRC_ROOT) / ".." / "explorer";
    ASSERT_TRUE(fs::exists(explorer_dir / "explorer.py"));

    // Drives ExplorerHandler.do_GET on a fake engine (no coin node, no socket)
    // and prints the raw HTTP response.
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
        return run_shell("python3 -I " + quote_sh(script.string()) + " " + quote_sh(explorer_dir.string()) + " "
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
    const ShellResult same = run_shell("python3 -I -c " + quote_sh(
        "import sys; sys.path.insert(0, sys.argv[1]); import explorer as e; "
        "sys.stdout.write(e.inject_analytics_tag(sys.argv[2], sys.argv[3]))")
        + " " + quote_sh(explorer_dir.string()) + " " + quote_sh(kPage) + " " + quote_sh(kId));
    std::string cpp = kPage;
    core::inject_analytics_tag(cpp, kId);
    EXPECT_EQ(same.out, cpp);
    const std::string nobody = "<html><head></head><p>x</p>";
    const ShellResult same2 = run_shell("python3 -I -c " + quote_sh(
        "import sys; sys.path.insert(0, sys.argv[1]); import explorer as e; "
        "sys.stdout.write(e.inject_analytics_tag(sys.argv[2], sys.argv[3]))")
        + " " + quote_sh(explorer_dir.string()) + " " + quote_sh(nobody) + " " + quote_sh(kId));
    std::string cpp2 = nobody;
    core::inject_analytics_tag(cpp2, kId);
    EXPECT_EQ(same2.out, cpp2);

    // --analytics-id with a bad value: refused before anything starts.
    const ShellResult refused = run_shell("python3 -I " + quote_sh((explorer_dir / "explorer.py").string())
                            + " --analytics-id " + quote_sh("G-ABCD'+x+'") + " 2>&1");
    EXPECT_NE(refused.status, 0);
    EXPECT_NE(refused.out.find("bad value: --analytics-id"), std::string::npos) << refused.out;

    std::error_code ec;
    fs::remove_all(dir, ec);
}
