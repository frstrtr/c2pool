// SPDX-License-Identifier: AGPL-3.0-or-later
// P5: one shared tx-hex vector per cached template.
//
// The serve path built a fresh copy of the template's tx hex for every job it
// issued: build_connection_coinbase's freeze_snapshot copied wd->m_tx_data_hex
// into a new vector once per session per notify. P5 encodes that vector once,
// when the template is stored, and every job built over the template shares it.
// The bytes a miner receives and the bodies a won block is assembled from must
// not change.
//
// This file pins that, in two layers:
//
//   * Golden serves (DashP5SharedTxHex.*Golden*). Digests of complete serves,
//     captured from the code BEFORE P5 and pinned here: every session, every
//     template, through the work-source API (template JSON, merkle branches,
//     coinbase parts and the whole frozen snapshot, tx bodies included) and
//     through a real core::StratumServer on loopback (each session with its own
//     extranonce1 and its own start difficulty; every mining.notify and
//     mining.set_difficulty on the wire). They pass on the pre-P5 code and must
//     keep passing.
//   * The P5 contract (pointer identity per template, a fresh vector after
//     every rebuild, invalidate and tip change, no vector on a copy, the live
//     hex gauge, the serve timing line): added with the change itself.
//
// Templates come from the stubbed dashd fallback, so each re-source stores a
// new DashWorkData instance exactly as production does.

#include <impl/dash/stratum/work_source.hpp>
#include <impl/dash/coinbase_builder.hpp>   // sha256d
#include <impl/dash/coin/vendor/bls_mode_guard.hpp>

#include <core/stratum_server.hpp>
#include <core/stratum_work_source.hpp>
#include <core/uint256.hpp>

#include <btclibs/base58.h>                 // EncodeBase58Check
#include <btclibs/util/strencodings.h>      // HexStr, ParseHex

#include <boost/asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstring>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

namespace asio = boost::asio;
using tcp  = asio::ip::tcp;
using json = nlohmann::json;
using namespace std::chrono_literals;
using dash::coin::DashWorkData;
using dash::stratum::DASHWorkSource;

// ── Fixture templates ────────────────────────────────────────────────────────

std::string body_hex(unsigned char tag, size_t n)
{
    std::vector<unsigned char> b(n);
    for (size_t i = 0; i < n; ++i)
        b[i] = static_cast<unsigned char>(tag ^ static_cast<unsigned char>(i * 31u));
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

uint256 body_txid(const std::string& hex)
{
    const auto b = ParseHex(hex);
    return dash::coinbase::sha256d(std::span<const unsigned char>(b.data(), b.size()));
}

std::vector<unsigned char> p2pkh(unsigned char fill)
{
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), 20, fill);
    s.push_back(0x88);
    s.push_back(0xac);
    return s;
}

// DASH mainnet P2PKH address (version 76) for a pubkey hash filled with `fill`.
std::string dash_address(unsigned char fill)
{
    std::vector<unsigned char> v = {76};
    v.insert(v.end(), 20, fill);
    return EncodeBase58Check(v);
}

const char* const kPrev1 = "00000000000000127a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677a";
const char* const kPrev2 = "00000000000000098877665544332211ffeeddccbbaa99887766554433221100";

DashWorkData make_template(const char* prev_hex, uint32_t height, uint64_t coinbase_value,
                           const std::vector<std::pair<unsigned char, size_t>>& bodies)
{
    DashWorkData w;
    w.m_version = 0x20000000;
    w.m_previous_block.SetHex(prev_hex);
    w.m_height         = height;
    w.m_coinbase_value = coinbase_value;
    w.m_bits           = 0x1913ab4fu;
    w.m_curtime        = 1764000000u + height;

    dash::coin::PackedPayment mn;
    {
        auto s = p2pkh(0x22);
        mn.payee = "!" + HexStr(std::span<const unsigned char>(s.data(), s.size()));
    }
    mn.amount = 100000000ULL;
    w.m_packed_payments.push_back(mn);
    w.m_payment_amount = mn.amount;

    for (const auto& [tag, n] : bodies) {
        w.m_tx_data_hex.push_back(body_hex(tag, n));
        w.m_tx_hashes.push_back(body_txid(w.m_tx_data_hex.back()));
        w.m_tx_fees.push_back(1000u + n);
    }
    return w;
}

// The template sequence every golden KAT walks:
//   A  six bodies of 1..999 bytes                          (first store)
//   B  the same tx set again                               (rebuild: bump_work_generation)
//   C  three other bodies, same tip                        (rebuild: bump_work_generation)
//   D  coinbase-only, the next tip                         (invalidate_template_cache)
DashWorkData tmpl_A()
{
    return make_template(kPrev1, 2583001u, 165000000ULL,
                         {{0x31, 1}, {0x32, 37}, {0x33, 120}, {0x34, 251}, {0x35, 999}, {0x36, 2}});
}
DashWorkData tmpl_B() { return tmpl_A(); }
DashWorkData tmpl_C()
{
    return make_template(kPrev1, 2583001u, 164990000ULL, {{0x41, 64}, {0x42, 300}, {0x43, 5}});
}
DashWorkData tmpl_D() { return make_template(kPrev2, 2583002u, 164400000ULL, {}); }

// A DASHWorkSource over an unpopulated coin state whose dashd fallback serves
// whatever `work` holds. The fallback may run on the stratum io thread.
struct Source {
    dash::coin::NodeCoinState coin_state;
    std::mutex   mu;
    DashWorkData work;

    void set(DashWorkData w)
    {
        std::lock_guard<std::mutex> lk(mu);
        work = std::move(w);
    }
    std::function<DashWorkData()> fallback()
    {
        return [this]() {
            std::lock_guard<std::mutex> lk(mu);
            return work;
        };
    }
    static DASHWorkSource::SubmitBlockFn submit()
    {
        return [](const std::vector<unsigned char>&, uint32_t, bool) { return true; };
    }
};

// A deterministic producer job (the run-loop's mint path), so the producer
// branch of build_connection_coinbase is served too.
std::optional<DASHWorkSource::ProducerJob> stub_producer_job(
    const uint256& prev_share, const std::vector<unsigned char>& script, const DashWorkData& wd)
{
    DASHWorkSource::ProducerJob pj;
    pj.gentx_bytes = {0x01, 0x00, 0x00, 0x00};
    pj.gentx_bytes.insert(pj.gentx_bytes.end(), script.begin(), script.end());
    for (int i = 0; i < 4; ++i)
        pj.gentx_bytes.push_back(static_cast<unsigned char>(wd.m_height >> (8 * i)));
    pj.gentx_bytes.push_back(static_cast<unsigned char>(wd.m_tx_hashes.size()));
    pj.nonce64_offset = pj.gentx_bytes.size();
    pj.gentx_bytes.insert(pj.gentx_bytes.end(), 8, 0x00);
    pj.gentx_bytes.insert(pj.gentx_bytes.end(), {0xde, 0xad, 0xbe, 0xef});
    pj.ref_hash       = prev_share;
    pj.share_bits     = 0x1e0fffffu;
    pj.share_max_bits = 0x1e0fffffu;
    return pj;
}

// ── Serve digests ────────────────────────────────────────────────────────────

std::string sha256d_hex(const std::string& s)
{
    return dash::coinbase::sha256d(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(s.data()), s.size())).GetHex();
}

// One session's serve, exactly the three calls core::StratumSession::
// send_notify_work makes, in its order. Every field of the result goes into
// the digest; the tx bodies go in by content (never by address).
struct Serve {
    json tmpl;
    std::vector<std::string> branches;
    core::stratum::CoinbaseResult cbr;
};

Serve serve_session(const DASHWorkSource& ws, const uint256& prev_share, const std::string& en1,
                    const std::vector<unsigned char>& script)
{
    Serve s;
    s.tmpl     = ws.get_current_work_template();
    s.branches = ws.get_stratum_merkle_branches();
    s.cbr      = ws.build_connection_coinbase(prev_share, en1, script, {});
    return s;
}

std::string serve_digest(const Serve& s)
{
    std::ostringstream o;
    o << s.tmpl.dump() << "|br:";
    for (const auto& b : s.branches) o << b << ',';
    const auto& c  = s.cbr;
    const auto& sn = c.snapshot;
    o << "|cb1:" << c.coinb1 << "|cb2:" << c.coinb2 << "|held:" << c.held
      << "|hdr:" << sn.has_header << ',' << sn.gbt_prevhash << ',' << sn.header_version << ','
      << sn.block_nbits_hex << ',' << sn.curtime << ',' << sn.height << "|sub:" << sn.subsidy
      << "|seg:" << sn.segwit_active << "|mweb:" << sn.mweb << ',' << sn.mweb_active
      << "|deg:" << sn.degraded << "|wc:" << sn.witness_commitment_hex << ','
      << sn.witness_root.GetHex() << "|ref:" << sn.frozen_ref.ref_hash.GetHex() << ','
      << sn.frozen_ref.bits << ',' << sn.frozen_ref.max_bits << "|fmb:";
    for (const auto& b : sn.frozen_ref.frozen_merkle_branches) o << b.GetHex() << ',';
    o << "|smb:";
    for (const auto& b : sn.merkle_branches) o << b << ',';
    o << "|tx:";
    if (!sn.tx_data)
        o << "null";
    else {
        o << sn.tx_data->size() << ':';
        for (const auto& h : *sn.tx_data) o << h << ',';
    }
    return sha256d_hex(o.str());
}

// Compare digests with the pinned golden list. On a mismatch every actual
// digest is printed, ready to paste (this is also how the list was captured,
// on the code before P5).
void expect_golden(const char* name, const std::vector<std::string>& actual,
                   const std::vector<std::string>& golden)
{
    bool ok = actual.size() == golden.size();
    for (size_t i = 0; ok && i < actual.size(); ++i) ok = actual[i] == golden[i];
    if (ok) return;
    std::ostringstream o;
    for (size_t i = 0; i < actual.size(); ++i)
        o << "P5-GOLDEN " << name << '[' << i << "] \"" << actual[i] << "\",\n";
    ADD_FAILURE() << name << ": " << actual.size() << " serves vs " << golden.size()
                  << " pinned; the serve bytes changed (or the list is being captured):\n"
                  << o.str();
}

struct SessionKey {
    uint256 prev_share;
    std::string en1;
    std::vector<unsigned char> script;
};

std::vector<SessionKey> api_sessions()
{
    std::vector<SessionKey> v;
    const unsigned char fills[] = {0x11, 0x33, 0x44, 0x55};
    for (size_t i = 0; i < 4; ++i) {
        SessionKey k;
        k.prev_share = uint256(std::vector<unsigned char>(32, static_cast<unsigned char>(0xa1 + i)));
        k.en1        = "0000000" + std::to_string(i + 1);
        k.script     = p2pkh(fills[i]);
        v.push_back(std::move(k));
    }
    SessionKey ownerless;   // a session before mining.authorize: no payout yet
    ownerless.prev_share = uint256(std::vector<unsigned char>(32, 0xa9));
    ownerless.en1        = "00000009";
    v.push_back(std::move(ownerless));
    return v;
}

// Walk A, B, C, D; serve every session on each; return the digests in order.
// `observe` sees every serve (template step, session index, serve).
template <typename Observe>
std::vector<std::string> walk_templates(Source& src, DASHWorkSource& ws, Observe&& observe)
{
    const auto sessions = api_sessions();
    std::vector<std::string> out;
    const DashWorkData steps[] = {tmpl_A(), tmpl_B(), tmpl_C(), tmpl_D()};
    for (size_t t = 0; t < 4; ++t) {
        src.set(steps[t]);
        if (t == 1 || t == 2) ws.bump_work_generation();
        if (t == 3) ws.invalidate_template_cache("kat: P5 template walk");
        for (size_t i = 0; i < sessions.size(); ++i) {
            const auto& k = sessions[i];
            Serve s = serve_session(ws, k.prev_share, k.en1, k.script);
            observe(t, i, s);
            out.push_back(serve_digest(s));
        }
        // A second serve of the same template by the first session (a VARDIFF
        // push or a periodic refresh on the same work generation).
        const auto& k = sessions[0];
        Serve again = serve_session(ws, k.prev_share, k.en1, k.script);
        observe(t, 0, again);
        out.push_back(serve_digest(again));
    }
    return out;
}

const std::vector<DashWorkData>& step_templates()
{
    static const std::vector<DashWorkData> v = {tmpl_A(), tmpl_B(), tmpl_C(), tmpl_D()};
    return v;
}

// ── Real stratum harness ────────────────────────────────────────────────────

// Records what every job is frozen with, then hands the result on untouched.
class RecordingWorkSource : public DASHWorkSource {
public:
    using DASHWorkSource::DASHWorkSource;

    struct Built {
        std::vector<unsigned char> script;
        uint32_t height{0};
        std::shared_ptr<const std::vector<std::string>> tx_data;   // the job's own pointer
    };

    core::stratum::CoinbaseResult build_connection_coinbase(
        const uint256& prev_share, const std::string& en1,
        const std::vector<unsigned char>& script,
        const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>& merged) const override
    {
        auto r = DASHWorkSource::build_connection_coinbase(prev_share, en1, script, merged);
        std::lock_guard<std::mutex> lk(mu_);
        built_.push_back(Built{script, r.snapshot.height, r.snapshot.tx_data});
        return r;
    }

    std::vector<Built> built() const
    {
        std::lock_guard<std::mutex> lk(mu_);
        return built_;
    }

private:
    mutable std::mutex mu_;
    mutable std::vector<Built> built_;
};

struct Stratum {
    asio::io_context ioc;
    Source src;
    std::shared_ptr<RecordingWorkSource> ws;
    std::unique_ptr<core::StratumServer> server;
    uint16_t port = 0;

    bool start()
    {
        ws = std::make_shared<RecordingWorkSource>(src.coin_state, src.fallback(), Source::submit());
        for (uint16_t p = 39711; p < 39811; ++p) {
            auto s = std::make_unique<core::StratumServer>(ioc, "127.0.0.1", p, ws);
            if (s->start()) {
                server = std::move(s);
                port = p;
                break;
            }
        }
        if (!server) return false;
        guard_.emplace(asio::make_work_guard(ioc));
        th_ = std::thread([this] { ioc.run(); });
        return true;
    }

    template <typename F>
    void on_io(F&& fn)
    {
        std::promise<void> done;
        asio::post(ioc, [&] { fn(); done.set_value(); });
        done.get_future().wait();
    }

    ~Stratum()
    {
        if (server) on_io([&] { server->stop(); });
        guard_.reset();
        ioc.stop();
        if (th_.joinable()) th_.join();
    }

private:
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> guard_;
    std::thread th_;
};

class Client {
public:
    Client() : sock_(io_) {}

    bool connect(uint16_t port)
    {
        boost::system::error_code ec;
        sock_.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port), ec);
        return !ec;
    }

    void send(const json& j)
    {
        const std::string line = j.dump() + "\n";
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(line), ec);
    }

    std::optional<std::string> read_line(std::chrono::milliseconds timeout)
    {
        std::optional<std::string> out;
        bool finished = false;
        asio::async_read_until(sock_, buf_, '\n', [&](boost::system::error_code ec, std::size_t) {
            finished = true;
            if (!ec) {
                std::istream is(&buf_);
                std::string line;
                std::getline(is, line);
                out = line;
            }
        });
        io_.restart();
        io_.run_for(timeout);
        if (!finished) {
            boost::system::error_code ec;
            sock_.cancel(ec);
            io_.restart();
            io_.run();
        }
        return out;
    }

    std::optional<json> wait_response(int id, std::chrono::milliseconds timeout = 5000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            auto line = read_line(500ms);
            if (!line) continue;
            json j = json::parse(*line, nullptr, false);
            if (j.is_discarded()) continue;
            record(j);
            if (j.contains("id") && !j["id"].is_null() && j["id"] == id) return j;
        }
        return std::nullopt;
    }

    bool subscribe()
    {
        send({{"id", 1}, {"method", "mining.subscribe"}, {"params", json::array()}});
        auto r = wait_response(1);
        if (!r || !(*r)["result"].is_array() || (*r)["result"].size() < 2) return false;
        extranonce1 = (*r)["result"][1].get<std::string>();
        return true;
    }

    bool authorize(const std::string& user, const std::string& password)
    {
        send({{"id", 2}, {"method", "mining.authorize"}, {"params", json::array({user, password})}});
        auto r = wait_response(2);
        return r && (*r)["result"].is_boolean() && (*r)["result"].get<bool>();
    }

    bool collect_notifies(size_t count, std::chrono::milliseconds timeout = 10000ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (notifies.size() < count && std::chrono::steady_clock::now() < deadline) {
            auto line = read_line(500ms);
            if (!line) continue;
            json j = json::parse(*line, nullptr, false);
            if (!j.is_discarded()) record(j);
        }
        return notifies.size() >= count;
    }

    // Everything the miner was sent, in order, except the job id (a process-
    // wide counter) and extranonce1 (likewise).
    std::string wire_digest() const { return sha256d_hex(wire_); }

    std::string extranonce1;
    std::vector<json> notifies;     // mining.notify params, in order
    std::vector<double> difficulties;

private:
    void record(const json& j)
    {
        if (!j.contains("method") || !j.contains("params") || !j["params"].is_array()) return;
        if (j["method"] == "mining.set_difficulty" && !j["params"].empty()) {
            difficulties.push_back(j["params"][0].get<double>());
            wire_ += "diff:" + j["params"][0].dump() + "\n";
        } else if (j["method"] == "mining.notify" && j["params"].size() >= 9) {
            notifies.push_back(j["params"]);
            json p = j["params"];
            p.erase(p.begin());   // job id
            wire_ += "notify:" + p.dump() + "\n";
        }
    }

    asio::io_context io_;
    tcp::socket sock_;
    asio::streambuf buf_;
    std::string wire_;
};

struct WireSession {
    unsigned char fill;
    const char* password;
};
const WireSession kWireSessions[] = {
    {0x11, "x,d=512"}, {0x33, "x,d=1024"}, {0x44, "x,d=2048"}, {0x55, "x,d=4096"},
};

// Connect the four sessions on template A, then walk B, C, D: each step is one
// notify_all (plus one more on A). Every session ends with six notifies:
// subscribe, authorize, A again, B, C, D.
struct WireRun {
    std::vector<std::unique_ptr<Client>> clients;
    bool ok{false};
};

WireRun run_wire_walk(Stratum& st)
{
    WireRun run;
    st.src.set(tmpl_A());
    if (!st.start()) return run;
    for (const auto& s : kWireSessions) {
        auto c = std::make_unique<Client>();
        if (!c->connect(st.port) || !c->subscribe()) return run;
        if (!c->authorize(dash_address(s.fill), s.password)) return run;
        if (!c->collect_notifies(2)) return run;
        run.clients.push_back(std::move(c));
    }
    auto step = [&](size_t want, auto&& event) {
        st.on_io([&] {
            event();
            st.server->notify_all();
        });
        for (auto& c : run.clients)
            if (!c->collect_notifies(want)) return false;
        return true;
    };
    if (!step(3, [] {})) return run;
    st.src.set(tmpl_B());
    if (!step(4, [&] { st.ws->bump_work_generation(); })) return run;
    st.src.set(tmpl_C());
    if (!step(5, [&] { st.ws->bump_work_generation(); })) return run;
    st.src.set(tmpl_D());
    if (!step(6, [&] { st.ws->invalidate_template_cache("kat: P5 wire walk"); })) return run;
    run.ok = true;
    return run;
}

// Pinned from the code before P5 (origin/master 8bae57628, the P5-GOLDEN lines
// of a run with these lists empty).
const std::vector<std::string> kGoldenApiNonProducer = {
    "30b6e1776ebdf9de2c1886f095be57cc061cf214ff9c9ee31c1b4de4c7e42038",
    "f3a20315f46c5e3ebf939a1ce5f77c873ed21b7ffddc0c8b8863a92f84dea312",
    "b4154618fd648a33fc178cc9c9bbbbf84fdb4fe52682a27528689667ca6d7fa1",
    "79d9b0f77df6531f841a8e3df3e5b1589997192aac136283c1a334d919c89cf2",
    "e00a351ba50682db11b7ab7d641b2edc745b0251a1674f839b74c38a82bda7ce",
    "30b6e1776ebdf9de2c1886f095be57cc061cf214ff9c9ee31c1b4de4c7e42038",
    "30b6e1776ebdf9de2c1886f095be57cc061cf214ff9c9ee31c1b4de4c7e42038",
    "f3a20315f46c5e3ebf939a1ce5f77c873ed21b7ffddc0c8b8863a92f84dea312",
    "b4154618fd648a33fc178cc9c9bbbbf84fdb4fe52682a27528689667ca6d7fa1",
    "79d9b0f77df6531f841a8e3df3e5b1589997192aac136283c1a334d919c89cf2",
    "e00a351ba50682db11b7ab7d641b2edc745b0251a1674f839b74c38a82bda7ce",
    "30b6e1776ebdf9de2c1886f095be57cc061cf214ff9c9ee31c1b4de4c7e42038",
    "5ee03c883ab70601fabd7ad163cccdb84131b319d64939a7fd5cacdc31a0f22f",
    "212ff3c9cbb290ef80e3603cdf69ded09246615a0ffc8fb26c2a6cd9ac4bd8b3",
    "f58c2be80c5d5532a0d6bd833d741d22716678bf3b1109841532fa2058c7c84c",
    "ddcc9492ca8d8f41371465e671d25162dc1b587bd97986694db6c0c6da2fbbc1",
    "da70bcabe4182090debb62869c1a6efd66c5ac6f21b0a6a00c5fcffee162bf41",
    "5ee03c883ab70601fabd7ad163cccdb84131b319d64939a7fd5cacdc31a0f22f",
    "6fa02e176b7c0f3cebfd0844f5a7e7833c06ceaa96c25ee0739902f873c7b0cf",
    "a154d74db6a7dc2e46175867e8c8193e9b40e483c8c5e59a0bf4f499680d7cda",
    "8a67c998f3d7b4fa9eef2dc9a42cd8b4ed2beace8659e29531925024b9ebffeb",
    "dbb27b1a3f29b8b677f95a8b5f21346efa63c6c2566202a8a832a243ee40d7fb",
    "1a230142fc6b6c619c1c205341220ac3afdd08123fa1f9493085a8e006d731fe",
    "6fa02e176b7c0f3cebfd0844f5a7e7833c06ceaa96c25ee0739902f873c7b0cf",
};
const std::vector<std::string> kGoldenApiProducer = {
    "29a662bcc73e58d7505795b0ffa3cd5e87a7b29c7dd9a5ec765d1196f1c1c105",
    "98dabac2f8b46296940188ed0b1873498354715b2791132543928e5e0f70c71e",
    "7a408720ffb969b6d84de43c5bec0cbd9885e6b9c5a98c1ecf11db621572da71",
    "9e647551529f18f127100d7b988d8ddbe85d7551e2d81ee92b49a9f04996c883",
    "8045f29e75e759dfa667cfb48c7c51dc06f6cdfdd4914035e1fa0176bb642b56",
    "29a662bcc73e58d7505795b0ffa3cd5e87a7b29c7dd9a5ec765d1196f1c1c105",
    "29a662bcc73e58d7505795b0ffa3cd5e87a7b29c7dd9a5ec765d1196f1c1c105",
    "98dabac2f8b46296940188ed0b1873498354715b2791132543928e5e0f70c71e",
    "7a408720ffb969b6d84de43c5bec0cbd9885e6b9c5a98c1ecf11db621572da71",
    "9e647551529f18f127100d7b988d8ddbe85d7551e2d81ee92b49a9f04996c883",
    "8045f29e75e759dfa667cfb48c7c51dc06f6cdfdd4914035e1fa0176bb642b56",
    "29a662bcc73e58d7505795b0ffa3cd5e87a7b29c7dd9a5ec765d1196f1c1c105",
    "6f3206cb4a6cb0fc382a8f77b809cfcaf6abdf4217f3276960b749eba3cff5aa",
    "1174d1e305e8ba93dcc87eec32b9e8c9b22294c05aa1e977f8382a6183658f66",
    "b2252fcff1405d1c3bb2ad712537410a543b8ba09feea4a902ece3a86138177c",
    "4d16c4a69ffe5da3560dd3927b5631e2fa7c55b928c66346fe9e2f24d07c9594",
    "01a4ae9f2c79c2e7e1829e0b25dcf6ebe0a735d0a58f05389a51365a811fa94d",
    "6f3206cb4a6cb0fc382a8f77b809cfcaf6abdf4217f3276960b749eba3cff5aa",
    "6800ab83c9f7612fc0a24110e7c0155abcd5f2ac7ebd9015382fcd191282dbcf",
    "85b9afdf9e21d2f3fc5d286c174cb6aa1be45ad85844db402908f5efc5e2efd4",
    "54e33b16fc13ebdd93e4d4269d72cbc500290facc6e15bce9d44fc1d04a53fc6",
    "c8b2da5e98e1890fa2ca7a567f1991ad4846575ab960f227a9b852f240e84f84",
    "8c536d15efd59e1fb8300405411d4b4242149a162268bba8fe879ecee9cc234b",
    "6800ab83c9f7612fc0a24110e7c0155abcd5f2ac7ebd9015382fcd191282dbcf",
};
const std::vector<std::string> kGoldenWire = {
    "d85bb4502bde818fb53ec4bd295f0bce53f527d35edca4af29643234b60de49f",
    "88b4d8314346b3865f23428cf869d516cd19d490672f0c972a71f83507f8a62f",
    "36f06334b40b009562cfa8c942a7bb00cdd608711eb2b43cf7e47183859f5bb0",
    "f770eb8d157a5bfbfc60c4f14575fa1a911e928ad2689d59c5c3d857c34836ad",
};

}  // namespace

// Every session's serve on every template, through the work-source API, is
// byte-for-byte the serve the pre-P5 code produced; and every job's bodies are
// exactly the template's bodies, in template order.
TEST(DashP5SharedTxHex, ApiServesMatchThePreP5GoldenPerSessionPerTemplate)
{
    Source src;
    DASHWorkSource ws(src.coin_state, src.fallback(), Source::submit());
    const auto digests = walk_templates(src, ws, [](size_t t, size_t i, const Serve& s) {
        ASSERT_TRUE(s.cbr.snapshot.tx_data) << "template " << t << " session " << i;
        EXPECT_EQ(*s.cbr.snapshot.tx_data, step_templates()[t].m_tx_data_hex)
            << "template " << t << " session " << i;
        EXPECT_EQ(s.cbr.snapshot.height, step_templates()[t].m_height);
    });
    ASSERT_EQ(digests.size(), 4u * 6u);
    expect_golden("kGoldenApiNonProducer", digests, kGoldenApiNonProducer);
}

// The same walk with the run-loop's producer job bound: the producer branch of
// build_connection_coinbase freezes its snapshot through the same code.
TEST(DashP5SharedTxHex, ProducerServesMatchThePreP5GoldenPerSessionPerTemplate)
{
    Source src;
    DASHWorkSource ws(src.coin_state, src.fallback(), Source::submit());
    ws.set_producer_job_fn(stub_producer_job);
    size_t producer_serves = 0;
    const auto digests = walk_templates(src, ws, [&](size_t t, size_t i, const Serve& s) {
        ASSERT_TRUE(s.cbr.snapshot.tx_data) << "template " << t << " session " << i;
        EXPECT_EQ(*s.cbr.snapshot.tx_data, step_templates()[t].m_tx_data_hex)
            << "template " << t << " session " << i;
        producer_serves += s.cbr.snapshot.frozen_ref.bits == 0x1e0fffffu ? 1 : 0;
    });
    EXPECT_EQ(producer_serves, 4u * 6u) << "every serve must take the producer branch";
    expect_golden("kGoldenApiProducer", digests, kGoldenApiProducer);
}

// Four real stratum sessions, each with its own extranonce1 and its own start
// difficulty: everything each one was sent (every mining.set_difficulty and
// every mining.notify but the job id) is what the pre-P5 code sent, and every
// job was frozen with exactly its template's bodies.
TEST(DashP5SharedTxHex, WireServesMatchThePreP5GoldenPerSession)
{
    Stratum st;
    auto run = run_wire_walk(st);
    ASSERT_TRUE(run.ok) << "the stratum walk did not complete";
    ASSERT_EQ(run.clients.size(), 4u);

    std::set<std::string> en1s;
    std::set<double> start_diffs;
    std::vector<std::string> digests;
    for (const auto& c : run.clients) {
        en1s.insert(c->extranonce1);
        ASSERT_FALSE(c->difficulties.empty());
        start_diffs.insert(c->difficulties.back());
        ASSERT_EQ(c->notifies.size(), 6u);
        digests.push_back(c->wire_digest());
    }
    EXPECT_EQ(en1s.size(), 4u) << "each session has its own extranonce1";
    EXPECT_EQ(start_diffs.size(), 4u) << "each session has its own difficulty";

    // Bodies: every job built for a session carries the bodies of the template
    // it was built over (the height tells the steps apart only at D, so match
    // on content: A, B and C differ from each other by body set or by count).
    const auto built = st.ws->built();
    ASSERT_GE(built.size(), 4u * 6u);
    for (const auto& b : built) {
        ASSERT_TRUE(b.tx_data);
        bool matches = false;
        for (const auto& t : step_templates())
            matches = matches || (*b.tx_data == t.m_tx_data_hex && b.height == t.m_height);
        EXPECT_TRUE(matches) << "a job carries bodies of no template (" << b.tx_data->size()
                             << " bodies at h=" << b.height << ")";
    }
    expect_golden("kGoldenWire", digests, kGoldenWire);
}
