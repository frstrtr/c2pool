// SPDX-License-Identifier: AGPL-3.0-or-later
// DashInjectModel — everything but sign() (that one is DashInjectSign.cpp in
// c2wallet-dash-tx). Lives in c2wallet-dash-common on the btclibs closure: it
// reaches the hdkeys key decoders and the key-free planners, never a signer
// header.
#include "DashInjectModelImpl.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"
#include "GovCollateral.hpp"
#include "InjectManifest.hpp"

// Reused M1-A hdkeys core (btclibs closure). NO dashscript / signer headers.
#include "../hdkeys/Bip32.hpp"
#include "../hdkeys/Bip38.hpp"
#include "../hdkeys/Derivation.hpp"
#include "../hdkeys/Descriptor.hpp"
#include "../hdkeys/HexUtil.hpp"
#include "../hdkeys/KeyImport.hpp"
#include "../hdkeys/Keystore.hpp"
#include "../hdkeys/Secp.hpp"

#include <algorithm>
#include <optional>
#include <utility>

namespace c2w::dash {

namespace {

// ── secret-handling helpers ─────────────────────────────────────────────────

// A std::string copy of (part of) a secret, wiped when it leaves scope.
struct WipedString {
    std::string s;
    explicit WipedString(std::string v) : s(std::move(v)) {}
    ~WipedString() { wipe(s); }
    WipedString(const WipedString&) = delete;
    WipedString& operator=(const WipedString&) = delete;
    static void wipe(std::string& v)
    {
        if (!v.empty()) secure::secure_wipe(&v[0], v.size());
        v.clear();
    }
};

std::string trimmed(const std::string& s)
{
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

uint8_t dash_wif_version(bool testnet) { return testnet ? 0xef : 0xcc; }

std::array<uint8_t, 20> h160_of(const std::vector<uint8_t>& pub)
{
    return hdkeys::hash160(pub.data(), pub.size());
}

// A FoundKey for a raw scalar. The address is computed, not assumed; the caller
// binds it.
FoundKey key_from_scalar(const uint8_t* sk32, bool compressed, const std::string& path, bool testnet)
{
    if (!hdkeys::Secp::instance().seckey_verify(sk32))
        throw DashAbort("the private key is out of range (must be 1 <= k < N)");
    std::vector<uint8_t> pub = hdkeys::Secp::instance().pubkey_create(sk32, compressed);
    if (pub.empty()) throw DashAbort("could not derive the public key");
    FoundKey k;
    k.priv.assign(sk32, 32);
    k.pub = std::move(pub);
    k.compressed = compressed;
    k.address = h160_to_addr(h160_of(k.pub), testnet);
    k.path = path + (compressed ? "" : " (uncompressed)");
    return k;
}

// Derive along a descriptor key's steps with the wildcard set to `index`.
std::optional<hdkeys::HDKey> derive_desc(const hdkeys::DescKey& dk, uint32_t index)
{
    hdkeys::HDKey node = *dk.node;
    for (size_t i = 0; i < dk.derivation.size(); ++i) {
        const uint32_t step = (static_cast<int>(i) == dk.wildcard_step) ? index : dk.derivation[i];
        auto child = node.derive_child(step);
        if (!child) return std::nullopt;
        node = std::move(*child);
    }
    return node;
}

std::vector<uint32_t> desc_path(const hdkeys::DescKey& dk, uint32_t index)
{
    std::vector<uint32_t> p = dk.origin_path;
    for (size_t i = 0; i < dk.derivation.size(); ++i)
        p.push_back((static_cast<int>(i) == dk.wildcard_step) ? index : dk.derivation[i]);
    return p;
}

std::string desc_path_label(const hdkeys::DescKey& dk, uint32_t index)
{
    std::string p = hdkeys::format_path(desc_path(dk, index));
    if (dk.origin_fingerprint.empty()) p = "(descriptor key)" + p.substr(1);
    else p = "[" + dk.origin_fingerprint + "]" + p;
    return p;
}

std::optional<FoundKey> scan_descriptor(const std::string& text, const std::array<uint8_t, 20>& want,
                                        uint32_t indices, bool testnet)
{
    // Checksum first, with our own wording: the parser's message for any other
    // failure can quote the key expression, so it is never surfaced.
    const size_t hash = text.find('#');
    if (hash != std::string::npos &&
        hdkeys::descriptor_checksum(text.substr(0, hash)) != text.substr(hash + 1))
        throw DashAbort("the descriptor checksum does not match — a character was altered");
    hdkeys::DescriptorParse dp = hdkeys::parse_descriptor(text);
    if (!dp.ok)
        throw DashAbort("the descriptor does not parse (the parser's message is withheld because it "
                        "can quote key material)");
    const hdkeys::Descriptor& d = dp.desc;
    if (d.has_checksum && !d.checksum_valid)
        throw DashAbort("the descriptor checksum does not match — a character was altered");
    if (d.type != hdkeys::DescType::P2PKH || d.keys.size() != 1)
        throw DashAbort(std::string("the descriptor is ") + hdkeys::to_string(d.type) +
                        "(...); a DASH funding key is a single-key pkh(...) descriptor");
    const hdkeys::DescKey& dk = d.keys[0];
    if (dk.has_extended) {
        if (!dk.node || !dk.node->has_private())
            throw DashAbort("the descriptor holds an extended PUBLIC key; signing needs its xprv");
        const uint32_t n = dk.wildcard_step >= 0 ? indices : 1;
        for (uint32_t i = 0; i < n; ++i) {
            auto leaf = derive_desc(dk, i);
            if (!leaf || !leaf->has_private()) continue;
            if (h160_of(leaf->pubkey()) != want) continue;
            return key_from_scalar(leaf->privkey().data(), true, desc_path_label(dk, i), testnet);
        }
        return std::nullopt;
    }
    if (!dk.scalar.empty()) {
        for (bool compressed : {true, false}) {
            auto pub = hdkeys::Secp::instance().pubkey_create(dk.scalar.data(), compressed);
            if (!pub.empty() && h160_of(pub) == want)
                return key_from_scalar(dk.scalar.data(), compressed, "descriptor key", testnet);
        }
        return std::nullopt;
    }
    throw DashAbort("the descriptor holds a public key only; signing needs a private key");
}

// An xprv found in a keystore: tried as a master key (BIP44 scan) and as an
// account-level key (chain/index scan). Compressed keys only (BIP32).
std::optional<FoundKey> scan_xprv(const hdkeys::HDKey& root, const std::array<uint8_t, 20>& want,
                                  const KeyScanRange& range, bool testnet)
{
    const uint32_t coin_type = testnet ? 1u : 5u;
    std::vector<uint32_t> chains = {0};
    if (range.scan_internal) chains.push_back(1);
    for (uint32_t a = 0; a < range.accounts; ++a)
        for (uint32_t c : chains)
            for (uint32_t i = 0; i < range.indices; ++i) {
                const auto path = hdkeys::build_bip_path(hdkeys::Purpose::BIP44, coin_type, a, c, i);
                auto leaf = root.derive_path(path);
                if (leaf && leaf->has_private() && h160_of(leaf->pubkey()) == want)
                    return key_from_scalar(leaf->privkey().data(), true,
                                           "keystore xprv " + hdkeys::format_path(path), testnet);
            }
    for (uint32_t c : chains)
        for (uint32_t i = 0; i < range.indices; ++i) {
            auto leaf = root.derive_path({c, i});
            if (leaf && leaf->has_private() && h160_of(leaf->pubkey()) == want)
                return key_from_scalar(leaf->privkey().data(), true,
                                       "keystore xprv (account key)/" + std::to_string(c) + "/" +
                                           std::to_string(i),
                                       testnet);
        }
    return std::nullopt;
}

std::optional<FoundKey> try_scalar(const secure::SecureBytes& sk, bool compressed,
                                   const std::array<uint8_t, 20>& want, const std::string& label,
                                   bool testnet)
{
    if (sk.size() != 32) return std::nullopt;
    auto pub = hdkeys::Secp::instance().pubkey_create(sk.data(), compressed);
    if (pub.empty() || h160_of(pub) != want) return std::nullopt;
    return key_from_scalar(sk.data(), compressed, label, testnet);
}

FoundKey load_from_keystore(const KeyInput& in, const std::string& funding,
                            const std::array<uint8_t, 20>& want, bool testnet)
{
    hdkeys::KeystoreImport ks = hdkeys::import_json_keystore(in.secret);
    struct ItemsWipe {
        std::vector<hdkeys::KeystoreItem>& items;
        ~ItemsWipe()
        {
            for (auto& it : items) {
                WipedString::wipe(it.text);
                WipedString::wipe(it.passphrase);
            }
        }
    } items_wipe{ks.items};
    if (!ks.ok) throw DashAbort("the keystore is not valid JSON");
    if (ks.items.empty()) throw DashAbort("the keystore holds no recognised key material");

    size_t n_wif = 0, n_raw = 0, n_mn = 0, n_xprv = 0;
    for (size_t k = 0; k < ks.items.size(); ++k) {
        hdkeys::KeystoreItem& it = ks.items[k];
        const std::string label = "keystore item " + std::to_string(k + 1) + " (" + it.source_field + ")";
        std::optional<FoundKey> hit;
        switch (it.kind) {
        case hdkeys::KeystoreItem::Kind::Wif:
            ++n_wif;
            hit = try_scalar(it.scalar, it.compressed, want, label, testnet);
            if (!hit) hit = try_scalar(it.scalar, !it.compressed, want, label, testnet);
            break;
        case hdkeys::KeystoreItem::Kind::RawHex:
            ++n_raw;
            hit = try_scalar(it.scalar, true, want, label, testnet);
            if (!hit) hit = try_scalar(it.scalar, false, want, label, testnet);
            break;
        case hdkeys::KeystoreItem::Kind::Mnemonic: {
            ++n_mn;
            const std::string& pass = it.passphrase.empty() ? in.passphrase : it.passphrase;
            try {
                hit = find_key_for_address(it.text, pass, funding, testnet, in.range);
            } catch (const DashAbort&) {
                hit.reset();
            }
            break;
        }
        case hdkeys::KeystoreItem::Kind::Xprv: {
            ++n_xprv;
            auto root = hdkeys::HDKey::parse(it.text);
            if (root && root->has_private()) hit = scan_xprv(*root, want, in.range, testnet);
            break;
        }
        }
        if (hit) return std::move(*hit);
    }
    throw DashAbort("none of the " + std::to_string(ks.items.size()) + " key item(s) in the keystore (" +
                    std::to_string(n_wif) + " WIF, " + std::to_string(n_raw) + " raw, " +
                    std::to_string(n_mn) + " mnemonic, " + std::to_string(n_xprv) +
                    " xprv) controls " + funding + " within the scan range. Nothing was bound.");
}

// ── public-data helpers for the cards ───────────────────────────────────────

std::string plural(size_t n, const char* one, const char* many)
{
    return std::to_string(n) + " " + (n == 1 ? one : many);
}

int64_t sum_of(const std::vector<Utxo>& v)
{
    int64_t s = 0;
    for (const Utxo& u : v) s += u.satoshis;
    return s;
}

std::string spk_hex_of(const std::string& address, bool testnet)
{
    const std::array<uint8_t, 25> spk = p2pkh_script(addr_to_h160(address, testnet));
    return hdkeys::to_hex(std::vector<uint8_t>(spk.begin(), spk.end()));
}

// Outputs of a raw legacy tx, parsed independently of the signer's parser.
struct RawOut {
    int64_t value;
    std::vector<uint8_t> script;
};

std::vector<RawOut> raw_outputs(const std::vector<uint8_t>& raw)
{
    size_t off = 0;
    auto need = [&](size_t n) {
        if (off + n > raw.size()) throw DashAbort("signed tx is truncated");
    };
    auto le = [&](int n) {
        need(static_cast<size_t>(n));
        uint64_t v = 0;
        for (int i = 0; i < n; ++i) v |= static_cast<uint64_t>(raw[off++]) << (8 * i);
        return v;
    };
    auto cs = [&]() -> uint64_t {
        need(1);
        const uint8_t b = raw[off++];
        if (b < 0xFD) return b;
        return le(b == 0xFD ? 2 : b == 0xFE ? 4 : 8);
    };
    le(4);
    const uint64_t nin = cs();
    for (uint64_t i = 0; i < nin; ++i) {
        need(36);
        off += 36;
        const uint64_t sl = cs();
        need(sl + 4);
        off += sl + 4;
    }
    const uint64_t nout = cs();
    std::vector<RawOut> outs;
    for (uint64_t i = 0; i < nout; ++i) {
        RawOut o;
        o.value = static_cast<int64_t>(le(8));
        const uint64_t sl = cs();
        need(sl);
        o.script.assign(raw.begin() + static_cast<long>(off), raw.begin() + static_cast<long>(off + sl));
        off += sl;
        outs.push_back(std::move(o));
    }
    le(4);
    if (off != raw.size()) throw DashAbort("signed tx has trailing bytes");
    return outs;
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// key loading + binding
// ═══════════════════════════════════════════════════════════════════════════

const char* key_source_name(KeySource s)
{
    switch (s) {
    case KeySource::Mnemonic: return "BIP39 mnemonic";
    case KeySource::Wif: return "WIF";
    case KeySource::Bip38: return "BIP38";
    case KeySource::Descriptor: return "descriptor";
    case KeySource::JsonKeystore: return "JSON keystore";
    }
    return "?";
}

void bind_found_key(const FoundKey& key, const std::string& funding_address, bool testnet)
{
    const std::array<uint8_t, 20> want = addr_to_h160(funding_address, testnet);
    if (key.priv.size() != 32 || (key.pub.size() != 33 && key.pub.size() != 65) ||
        key.compressed != (key.pub.size() == 33))
        throw DashAbort("the key is malformed (scalar or pubkey length) — refusing to bind");
    if (key.address != funding_address)
        throw DashAbort("the key is for " + key.address + ", not the funding address " +
                        funding_address + " — refusing to bind");
    const std::array<uint8_t, 20> h = h160_of(key.pub);
    if (h != want)
        throw DashAbort("the key's pubkey does not hash to the funding address — refusing to bind");
    if (h160_to_addr(h, testnet) != funding_address)
        throw DashAbort("internal cross-check failed: the key's hash160 re-encodes to another "
                        "address — refusing to bind");
}

FoundKey load_funding_key(const KeyInput& in, const std::string& funding_address, bool testnet)
{
    const std::array<uint8_t, 20> want = addr_to_h160(funding_address, testnet);
    if ((in.source == KeySource::Mnemonic || in.source == KeySource::Descriptor ||
         in.source == KeySource::JsonKeystore) &&
        (in.range.accounts == 0 || in.range.indices == 0))
        throw DashAbort("key scan range is empty (accounts and indices must be >= 1)");
    std::optional<FoundKey> k;
    switch (in.source) {
    case KeySource::Mnemonic:
        k = find_key_for_address(in.secret, in.passphrase, funding_address, testnet, in.range);
        break;
    case KeySource::Wif: {
        WipedString wif(trimmed(in.secret));
        hdkeys::WifDecode d = hdkeys::decode_wif(wif.s);
        if (!d.ok)
            throw DashAbort("the WIF does not decode (base58 checksum, length or key range) — "
                            "nothing was bound");
        if (d.version != dash_wif_version(testnet))
            throw DashAbort("the WIF carries version byte " + std::to_string(d.version) +
                            ", not DASH " + (testnet ? "testnet (239)" : "mainnet (204)") +
                            ": re-export it as a DASH WIF");
        k = key_from_scalar(d.scalar.data(), d.compressed, "imported WIF key", testnet);
        break;
    }
    case KeySource::Bip38: {
        WipedString enc(trimmed(in.secret));
        hdkeys::Bip38Decode d =
            hdkeys::decode_bip38(enc.s, in.passphrase, {p2pkh_version(testnet), 0x00});
        if (!d.ok) throw DashAbort("BIP38: " + d.error + " — nothing was bound");
        const bool dash_hash = d.address_version == p2pkh_version(testnet);
        k = key_from_scalar(d.scalar.data(), d.compressed,
                            std::string("BIP38 key (address hash over the ") +
                                (dash_hash ? "DASH" : "BTC") + " address)",
                            testnet);
        break;
    }
    case KeySource::Descriptor: {
        WipedString text(trimmed(in.secret));
        k = scan_descriptor(text.s, want, in.range.indices, testnet);
        if (!k)
            throw DashAbort("no index 0.." + std::to_string(in.range.indices - 1) +
                            " of the descriptor produces " + funding_address +
                            ". Nothing was bound.");
        break;
    }
    case KeySource::JsonKeystore:
        k = load_from_keystore(in, funding_address, want, testnet);
        break;
    }
    if (!k) throw DashAbort("no key was produced");
    bind_found_key(*k, funding_address, testnet);
    return std::move(*k);
}

// ═══════════════════════════════════════════════════════════════════════════
// the state machine
// ═══════════════════════════════════════════════════════════════════════════

const char* inject_stage_name(InjectStage s)
{
    switch (s) {
    case InjectStage::Empty: return "empty";
    case InjectStage::Imported: return "imported";
    case InjectStage::Screened: return "screened";
    case InjectStage::Planned: return "planned";
    case InjectStage::KeyBound: return "key bound";
    case InjectStage::Signed: return "signed";
    }
    return "?";
}

void DashInjectModel::Impl::wipe_key()
{
    if (key) {
        key.reset(); // ~FoundKey -> ~SecureBytes zeroizes the scalar
        ++keys_wiped;
    }
}

void DashInjectModel::Impl::clear_gate()
{
    reviewed = false;
    burn_ack = false;
    WipedString::wipe(typed);
}

void DashInjectModel::Impl::drop_after(InjectStage keep)
{
    clear_gate();
    wipe_key();
    signed_txs.clear();
    inject_file.clear();
    manifest.clear();
    sign_card.clear();
    if (keep < InjectStage::KeyBound) {
        key_path.clear();
        key_compressed = true;
    }
    if (keep < InjectStage::Planned) {
        sweep.reset();
        coll.reset();
        chosen.clear();
        not_selected = 0;
        plan_params = PlanParams{};
    }
    if (keep < InjectStage::Screened) {
        screen = TargetScreen{};
        screen_params = ScreenParams{};
    }
    if (keep < InjectStage::Imported) imp = UtxoImport{};
    if (stage > keep) stage = keep;
}

void DashInjectModel::Impl::require(InjectStage at_least, const char* what) const
{
    if (stage < at_least)
        throw DashAbort(std::string(what) + ": the model is at stage \"" + inject_stage_name(stage) +
                        "\"; stage \"" + inject_stage_name(at_least) +
                        "\" must be done first (no stage can be skipped)");
}

void DashInjectModel::Impl::run_plan(PubkeyEncoding enc)
{
    const PlanParams& p = plan_params;
    const bool collateral = p.mode == OutputMode::Collateral;
    const bool relay = p.fee_mode == FeeMode::Relay;
    if (relay) {
        if (p.fee_rate_per_byte < kMinRelayFeePerByte || p.fee_rate_per_byte > kMaxRelayFeePerByte)
            throw DashAbort("RELAY fee rate " + std::to_string(p.fee_rate_per_byte) +
                            " duffs/B is outside [" + std::to_string(kMinRelayFeePerByte) + ", " +
                            std::to_string(kMaxRelayFeePerByte) + "]");
    } else if (p.fee_rate_per_byte != 0) {
        throw DashAbort("the zero-fee (pin/inject) mode takes fee rate 0; a fee-paying tx is the "
                        "RELAY mode");
    }
    if (collateral && p.max_inputs_per_tx != 0)
        throw DashAbort("a collateral is ONE tx and is never split: max_inputs_per_tx must be 0");
    if (!collateral && (!p.gov_hash_display.empty() || !p.change_address.empty()))
        throw DashAbort("a consolidation takes a destination, not a gov hash or change address");

    // The mature inputs, optionally capped to the N oldest.
    std::vector<Utxo> pick = screen.screen.spendable;
    size_t left_out = 0;
    if (p.input_limit > 0 && p.input_limit < pick.size()) {
        std::stable_sort(pick.begin(), pick.end(), [](const Utxo& a, const Utxo& b) {
            if (a.height != b.height) return a.height < b.height;
            if (a.txid != b.txid) return a.txid < b.txid;
            return a.vout < b.vout;
        });
        left_out = pick.size() - p.input_limit;
        pick.resize(p.input_limit);
    }
    // The planner re-screens what it is given; hand it the immature and dust
    // rows too so its summary lists them exactly as stage 2 did.
    std::vector<Utxo> offered = pick;
    offered.insert(offered.end(), screen.screen.immature.begin(), screen.screen.immature.end());
    offered.insert(offered.end(), screen.screen.dust.begin(), screen.screen.dust.end());

    std::optional<SweepBatchPlan> new_sweep;
    std::optional<CollateralPlan> new_coll;
    if (!collateral) {
        SweepRequest r;
        r.funding_address = imp.address;
        r.destination_address = p.destination;
        r.utxos = std::move(offered);
        r.min_confirmations = screen_params.min_confirmations;
        r.dust_floor = screen_params.dust_floor;
        r.testnet = testnet;
        r.max_inputs_per_tx = p.max_inputs_per_tx ? p.max_inputs_per_tx : caps::kMaxInjectInputs;
        r.key_encoding = enc;
        r.fee_mode = p.fee_mode;
        r.fee_rate_per_byte = relay ? p.fee_rate_per_byte : 0;
        new_sweep = plan_sweep(r);
    } else {
        const int64_t mature = sum_of(pick);
        if (mature < kGovernanceProposalFee)
            throw DashAbort("INSUFFICIENT: mature " + format_dash(mature) + " DASH < 1.00000000 (short " +
                            format_dash(kGovernanceProposalFee - mature) + " DASH) at target height " +
                            std::to_string(screen.target_height) + "; " +
                            plural(screen.screen.immature.size(), "immature UTXO", "immature UTXOs") +
                            " and " + plural(screen.screen.dust.size(), "dust UTXO", "dust UTXOs") +
                            " were left out. Nothing was built.");
        CollateralRequest c;
        c.funding_address = imp.address;
        c.change_address = p.change_address;
        c.gov_hash_display = p.gov_hash_display;
        c.utxos = std::move(offered);
        c.min_confirmations = screen_params.min_confirmations;
        c.dust_floor = screen_params.dust_floor;
        c.testnet = testnet;
        c.fee_mode = p.fee_mode;
        c.fee_rate = relay ? p.fee_rate_per_byte * 1000 : 0; // duffs/B -> duffs/kB
        c.sweep_all = true;
        c.key_encoding = enc;
        new_coll = plan_collateral(c);
    }
    sweep = std::move(new_sweep);
    coll = std::move(new_coll);
    chosen = std::move(pick);
    not_selected = left_out;
}

void DashInjectModel::Impl::finish_signed(std::vector<SignedTx> txs)
{
    const bool collateral = coll.has_value();
    const size_t n_planned = collateral ? 1 : (sweep ? sweep->txs.size() : 0);
    if (txs.size() != n_planned || txs.empty())
        throw DashAbort("signed " + std::to_string(txs.size()) + " tx(s) for a plan of " +
                        std::to_string(n_planned) + " — refusing to emit");

    ManifestData md;
    md.testnet = testnet;
    md.mode = collateral ? "collateral" : "consolidate";
    md.fee_mode = plan_params.fee_mode;
    md.fee_rate_per_byte = plan_params.fee_mode == FeeMode::Relay ? plan_params.fee_rate_per_byte : 0;
    md.funding_address = imp.address;
    md.destination = collateral ? coll->change_address : sweep->destination_address;
    md.gov_hash = collateral ? coll->gov_hash_display : std::string();

    std::vector<Utxo> all_inputs;
    for (size_t i = 0; i < txs.size(); ++i) {
        const SignedTx& st = txs[i];
        const std::string label = "signed tx " + std::to_string(i + 1);
        auto raw = hdkeys::from_hex(st.hex);
        if (!raw || raw->empty()) throw DashAbort(label + " is not hex");
        const std::string raw_str(raw->begin(), raw->end());
        if (sha256d_display_hex(raw_str) != st.txid)
            throw DashAbort(label + ": txid does not hash from the bytes — refusing to emit");
        if (st.size != raw->size())
            throw DashAbort(label + ": size disagrees with the bytes — refusing to emit");

        ManifestTx mt;
        mt.txid = st.txid;
        mt.size = st.size;
        std::vector<std::pair<int64_t, std::vector<uint8_t>>> want_outs;
        if (collateral) {
            mt.est_signed_bytes = coll->est_signed_bytes;
            mt.fee = coll->fee;
            mt.inputs = coll->selected;
            want_outs.push_back({kGovernanceProposalFee, coll->op_return_script});
            if (coll->change > 0) {
                auto cs = hdkeys::from_hex(spk_hex_of(coll->change_address, testnet));
                want_outs.push_back({coll->change, *cs});
            }
        } else {
            const SweepTxPlan& tp = sweep->txs[i];
            mt.est_signed_bytes = tp.est_signed_bytes;
            mt.fee = tp.fee;
            mt.inputs = tp.inputs;
            want_outs.push_back({tp.value_out, tp.dest_spk});
        }
        if (st.size > mt.est_signed_bytes)
            throw DashAbort(label + ": " + std::to_string(st.size) + " B exceeds the plan's worst-case " +
                            std::to_string(mt.est_signed_bytes) + " B — refusing to emit");
        if (plan_params.fee_mode == FeeMode::Relay &&
            mt.fee < kMinRelayFeePerByte * static_cast<int64_t>(st.size))
            throw DashAbort(label + ": fee " + std::to_string(mt.fee) + " duffs is below dashd's " +
                            std::to_string(kMinRelayFeePerByte) + " duff/B minimum relay fee for " +
                            std::to_string(st.size) + " B — raise the fee rate. Nothing was emitted.");
        // The outputs, re-read from the signed bytes, must be the planned ones.
        const std::vector<RawOut> outs = raw_outputs(*raw);
        if (outs.size() != want_outs.size())
            throw DashAbort(label + ": output count differs from the plan — refusing to emit");
        for (size_t o = 0; o < outs.size(); ++o) {
            if (outs[o].value != want_outs[o].first || outs[o].script != want_outs[o].second)
                throw DashAbort(label + ": output " + std::to_string(o) +
                                " differs from the plan — refusing to emit");
            ManifestOutput mo;
            mo.value = outs[o].value;
            mo.script_hex = hdkeys::to_hex(outs[o].script);
            const bool op_return = !outs[o].script.empty() && outs[o].script[0] == 0x6a;
            mo.kind = op_return ? "op_return" : "p2pkh";
            if (!op_return && outs[o].script.size() == 25) {
                std::array<uint8_t, 20> h{};
                std::copy(outs[o].script.begin() + 3, outs[o].script.begin() + 23, h.begin());
                mo.address = h160_to_addr(h, testnet);
            }
            mt.value_out += mo.value;
            mt.outputs.push_back(std::move(mo));
        }
        all_inputs.insert(all_inputs.end(), mt.inputs.begin(), mt.inputs.end());
        md.txs.push_back(std::move(mt));
    }

    std::string file = emit_inject_file(txs);
    md.hex_file = file;
    md.intake_source = utxo_source_name(imp.source);
    md.screen_tip_height = imp.tip_height;
    md.screen_tip_hash = imp.tip_hash;
    md.target_height = screen.target_height;
    md.min_confirmations = screen.min_confirmations;
    md.safe_from_height = safe_from_height(all_inputs, imp.tip_height);
    for (const Utxo& u : all_inputs) {
        const int64_t h = effective_height(u, imp.tip_height);
        if (h <= 0) { md.youngest_input_height = 0; break; }
        md.youngest_input_height = std::max(md.youngest_input_height, h);
    }
    md.immature = screen.screen.immature;
    md.dust_count = screen.screen.dust.size();
    md.dust_floor = screen.dust_floor;
    md.not_selected = not_selected;
    md.key_source = key_source_name(key_source);
    md.key_path = key_path;
    md.key_encoding = key_compressed ? "compressed" : "uncompressed";
    std::string man = build_inject_manifest(md);

    std::string card = "SIGNED and independently re-verified: " + plural(txs.size(), "tx", "txs") + " (" +
                       (plan_params.fee_mode == FeeMode::Relay ? "RELAY, fee-paying" : "zero-fee, pin/inject") +
                       ")\n";
    for (size_t i = 0; i < md.txs.size(); ++i) {
        const ManifestTx& t = md.txs[i];
        card += "  tx " + std::to_string(i + 1) + ": " + t.txid + "\n      " + std::to_string(t.size) +
                " B (est " + std::to_string(t.est_signed_bytes) + "), " + std::to_string(t.inputs.size()) +
                " in / " + std::to_string(t.outputs.size()) + " out, out " + format_dash(t.value_out) +
                " DASH, fee " + format_dash(t.fee) + " DASH\n";
    }
    card += "hex file sha256d: " + sha256d_display_hex(file) + "\n";
    card += "hex file sha256:  " + sha256_hex(file) + "  (compare with sha256sum on the online host)\n";
    if (md.safe_from_height > 0)
        card += "admissible in any block at height >= " + std::to_string(md.safe_from_height) + "\n";
    card += "the key was wiped after signing.\n";

    signed_txs = std::move(txs);
    inject_file = std::move(file);
    manifest = std::move(man);
    sign_card = std::move(card);
    stage = InjectStage::Signed;
}

DashInjectModel::DashInjectModel(bool testnet) : p_(std::make_unique<Impl>()) { p_->testnet = testnet; }

DashInjectModel::~DashInjectModel() = default;

bool DashInjectModel::testnet() const { return p_->testnet; }
InjectStage DashInjectModel::stage() const { return p_->stage; }

void DashInjectModel::reset()
{
    p_->drop_after(InjectStage::Empty);
}

// ── 1. import ────────────────────────────────────────────────────────────────

void DashInjectModel::import_utxos(const std::string& json, int64_t tip_height,
                                   const std::string& expected_address)
{
    Impl& m = *p_;
    m.drop_after(InjectStage::Empty); // a re-import wipes everything, the key included
    UtxoImport imp = parse_utxo_json(json, tip_height, m.testnet);
    if (!expected_address.empty() && expected_address != imp.address)
        throw DashAbort("the UTXO list pays " + imp.address + ", not the expected funding address " +
                        expected_address);
    m.imp = std::move(imp);
    m.stage = InjectStage::Imported;
}

const UtxoImport& DashInjectModel::utxo_import() const
{
    p_->require(InjectStage::Imported, "utxo_import");
    return p_->imp;
}

std::string DashInjectModel::import_card() const
{
    const Impl& m = *p_;
    if (m.stage < InjectStage::Imported) return "no UTXO list imported";
    const UtxoImport& i = m.imp;
    int64_t hmin = 0, hmax = 0;
    for (const Utxo& u : i.utxos) {
        if (u.height <= 0) continue;
        hmin = hmin == 0 ? u.height : std::min(hmin, u.height);
        hmax = std::max(hmax, u.height);
    }
    std::string s;
    s += "source:          " + std::string(utxo_source_name(i.source)) + "\n";
    s += "funding address: " + i.address + "  (" + (m.testnet ? "testnet" : "mainnet") + ")\n";
    s += "tip height:      " + (i.tip_height > 0 ? std::to_string(i.tip_height) : std::string("unknown")) +
         (i.tip_hash.empty() ? std::string() : "  (" + i.tip_hash + ")") + "\n";
    s += "UTXOs:           " + std::to_string(i.utxos.size()) + ", " + format_dash(i.total) + " DASH\n";
    if (hmax > 0) s += "heights:         " + std::to_string(hmin) + " .. " + std::to_string(hmax) + "\n";
    s += std::string("coinbase flags:  ") +
         (i.coinbase_flags ? "present (gettxout)"
                           : "absent: every UTXO is held to the coinbase rule (>= 100 confirmations)") +
         "\n";
    return s;
}

// ── 2. screen ────────────────────────────────────────────────────────────────

void DashInjectModel::rescreen(const ScreenParams& params)
{
    Impl& m = *p_;
    m.require(InjectStage::Imported, "rescreen");
    m.drop_after(InjectStage::Imported);
    ScreenParams sp = params;
    if (sp.target_height == 0) {
        if (m.imp.tip_height <= 0)
            throw DashAbort("the tip is unknown: give the target landing height explicitly");
        sp.target_height = m.imp.tip_height + kDefaultTargetOffset;
    }
    if (sp.min_confirmations < 1) throw DashAbort("min_confirmations must be >= 1");
    TargetScreen ts = rescreen_at_height(m.imp.utxos, addr_to_h160(m.imp.address, m.testnet), m.imp.tip_height,
                                         sp.target_height, sp.min_confirmations, sp.dust_floor, true);
    m.screen_params = sp;
    m.screen = std::move(ts);
    m.stage = InjectStage::Screened;
}

const TargetScreen& DashInjectModel::target_screen() const
{
    p_->require(InjectStage::Screened, "target_screen");
    return p_->screen;
}

std::string DashInjectModel::screen_card() const
{
    const Impl& m = *p_;
    if (m.stage < InjectStage::Screened) return "not screened";
    const TargetScreen& t = m.screen;
    std::string s;
    s += "target landing height " + std::to_string(t.target_height) + " (screened tip " +
         (t.tip_height > 0 ? std::to_string(t.tip_height) : std::string("unknown")) + ", min confirmations " +
         std::to_string(t.min_confirmations) + ", dust floor " + std::to_string(t.dust_floor) + " duffs)\n";
    s += "spendable: " + std::to_string(t.screen.spendable.size()) + " UTXOs, " +
         format_dash(sum_of(t.screen.spendable)) + " DASH\n";
    s += "immature:  " + std::to_string(t.screen.immature.size()) + " UTXOs, " +
         format_dash(sum_of(t.screen.immature)) + " DASH\n";
    s += "dust:      " + std::to_string(t.screen.dust.size()) + " UTXOs, " +
         format_dash(sum_of(t.screen.dust)) + " DASH\n";
    if (t.safe_from_height > 0)
        s += "safe from height " + std::to_string(t.safe_from_height) +
             ": every spendable input is consensus-mature in any block at or above it (youngest input height " +
             std::to_string(t.youngest_height) + ")\n";
    else
        s += "safe-from height unknown (an input has no height)\n";
    for (const Utxo& u : t.screen.immature) {
        const int64_t n = std::max<int64_t>(0, confirmations_needed(u, t.min_confirmations) - u.confirmations);
        s += "  immature " + u.txid + ":" + std::to_string(u.vout) + "  " + format_dash(u.satoshis) +
             " DASH  height " + std::to_string(u.height) + "  matures in " + std::to_string(n) +
             (n == 1 ? " block\n" : " blocks\n");
    }
    return s;
}

// ── 3. plan ──────────────────────────────────────────────────────────────────

void DashInjectModel::plan(const PlanParams& params)
{
    Impl& m = *p_;
    m.require(InjectStage::Screened, "plan");
    m.drop_after(InjectStage::Screened); // a re-plan wipes the key
    m.plan_params = params;
    try {
        m.run_plan(PubkeyEncoding::Unknown);
    } catch (...) {
        m.drop_after(InjectStage::Screened);
        throw;
    }
    m.stage = InjectStage::Planned;
}

const PlanParams& DashInjectModel::plan_params() const
{
    p_->require(InjectStage::Planned, "plan_params");
    return p_->plan_params;
}

std::string DashInjectModel::plan_summary() const
{
    const Impl& m = *p_;
    if (m.stage < InjectStage::Planned) return "not planned";
    std::string s = m.sweep ? m.sweep->summary : m.coll->summary;
    if (m.sweep && m.sweep->txs.size() > 1)
        s += "SPLIT: " + std::to_string(m.sweep->txs.size()) +
             " txs, emitted as that many lines of one .hex file\n";
    if (m.not_selected)
        s += "not selected (input limit " + std::to_string(m.plan_params.input_limit) + "): " +
             std::to_string(m.not_selected) + " mature UTXOs stay unspent for a later plan\n";
    if (destination_is_external())
        s += std::string("EXTERNAL: the ") + (m.coll ? "change" : "destination") +
             " is NOT the funding address — funds leave this address\n";
    const int64_t safe = plan_safe_from_height();
    if (safe > 0)
        s += "admissible in any block at height >= " + std::to_string(safe) + " (target " +
             std::to_string(m.screen.target_height) + ")\n";
    s += std::string("pubkey encoding for the size estimate: ") +
         (m.stage >= InjectStage::KeyBound ? (m.key_compressed ? "compressed (key bound)" : "uncompressed (key bound)")
                                           : "unknown until the key is bound (worst case)") +
         "\n";
    return s;
}

size_t DashInjectModel::planned_tx_count() const
{
    const Impl& m = *p_;
    if (m.stage < InjectStage::Planned) return 0;
    return m.sweep ? m.sweep->txs.size() : 1;
}

int64_t DashInjectModel::planned_fee() const
{
    const Impl& m = *p_;
    if (m.stage < InjectStage::Planned) return 0;
    return m.sweep ? m.sweep->total_fee : m.coll->fee;
}

bool DashInjectModel::destination_is_external() const
{
    const Impl& m = *p_;
    if (m.stage < InjectStage::Planned) return false;
    const std::string& out = m.sweep ? m.sweep->destination_address : m.coll->change_address;
    return out != m.imp.address;
}

int64_t DashInjectModel::plan_safe_from_height() const
{
    const Impl& m = *p_;
    if (m.stage < InjectStage::Planned) return 0;
    std::vector<Utxo> ins;
    if (m.sweep)
        for (const SweepTxPlan& t : m.sweep->txs) ins.insert(ins.end(), t.inputs.begin(), t.inputs.end());
    else
        ins = m.coll->selected;
    return safe_from_height(ins, m.imp.tip_height);
}

const SweepBatchPlan* DashInjectModel::sweep_plan() const
{
    return p_->stage >= InjectStage::Planned && p_->sweep ? &*p_->sweep : nullptr;
}

const CollateralPlan* DashInjectModel::collateral_plan() const
{
    return p_->stage >= InjectStage::Planned && p_->coll ? &*p_->coll : nullptr;
}

// ── 4. key ───────────────────────────────────────────────────────────────────

void DashInjectModel::load_key(const KeyInput& in)
{
    Impl& m = *p_;
    m.require(InjectStage::Planned, "load_key");
    m.drop_after(InjectStage::Planned); // replaces (and wipes) any key held
    FoundKey k = load_funding_key(in, m.imp.address, m.testnet);
    m.key = std::make_unique<FoundKey>(std::move(k));
    m.key_source = in.source;
    m.key_path = m.key->path;
    m.key_compressed = m.key->compressed;
    try {
        m.run_plan(m.key_compressed ? PubkeyEncoding::Compressed : PubkeyEncoding::Uncompressed);
    } catch (...) {
        m.drop_after(InjectStage::Planned);
        throw;
    }
    m.stage = InjectStage::KeyBound;
}

bool DashInjectModel::has_key() const { return static_cast<bool>(p_->key); }

std::string DashInjectModel::key_card() const
{
    const Impl& m = *p_;
    if (!m.key)
        return m.stage == InjectStage::Signed ? "no key held (wiped after signing)" : "no key bound";
    return "key: " + m.key_path + " (" + (m.key_compressed ? "compressed" : "uncompressed") + ") via " +
           key_source_name(m.key_source) + "\ncontrols " + m.imp.address +
           " (bound on the address AND hash160(pubkey))\n";
}

size_t DashInjectModel::keys_wiped() const { return p_->keys_wiped; }

// ── 5. gate + outputs (sign() is DashInjectSign.cpp) ─────────────────────────

void DashInjectModel::set_gate(bool reviewed, bool burn_acknowledged, const std::string& typed_word)
{
    Impl& m = *p_;
    m.reviewed = reviewed;
    m.burn_ack = burn_acknowledged;
    m.typed = typed_word;
}

bool DashInjectModel::armed() const
{
    const Impl& m = *p_;
    if (m.stage != InjectStage::KeyBound || !m.key) return false;
    if (!m.reviewed || m.typed != kSpendWord) return false;
    if (m.coll && !m.burn_ack) return false;
    return true;
}

const std::vector<SignedTx>& DashInjectModel::signed_txs() const { return p_->signed_txs; }
const std::string& DashInjectModel::inject_file() const { return p_->inject_file; }
const std::string& DashInjectModel::manifest_json() const { return p_->manifest; }

std::string DashInjectModel::sign_card() const
{
    return p_->stage == InjectStage::Signed ? p_->sign_card : std::string("not signed");
}

} // namespace c2w::dash
