// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion, slice S-B) — the shared scan types.
//
// A scan reads the unspent outputs of up to 16 P2PKH addresses from one live
// source at one tip and returns them in the signer's own UtxoImport shape
// (UtxoIntake.hpp, c2wallet-dash-plan): rows sorted by (height, txid, vout),
// confirmations = tip - height + 1, the coinbase flag KNOWN for every row.
// Outputs a source reports as spent in its mempool are listed separately and
// never appear in the rows.
//
// Sources (one interface, two implementations):
//   SourceDashd   dashd JSON-RPC over the RpcApi seam: getaddressutxos
//                 (addressindex), else scantxoutset; gettxout per row.
//   SourceC2pool  the c2pool node's GET /api/utxo/scan over sched::NodeApi.
// CrossCheck.hpp runs both at one tip and refuses any difference.
//
// Everything here is PUBLIC chain data and key-free: the companion library
// that contains it is covered by ci/check_key_free.sh. Every refusal is a
// ScanRefusal carrying a stable cause name (below) and a human detail.

#include "../../family/bitcoin/dash/UtxoIntake.hpp" // UtxoImport / Utxo (key-free plan library)

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace c2w::companion::scan {

inline constexpr size_t kMaxScanAddresses = 16;

// Source names, as the sidecar's source.kind records them.
inline constexpr const char* kSourceDashdIndex = "dashd-addressindex";
inline constexpr const char* kSourceDashdScan = "dashd-scantxoutset";
inline constexpr const char* kSourceC2pool = "c2pool-utxo-scan";
inline constexpr const char* kSourceBoth = "both";

namespace cause {
inline constexpr const char* kBadAddress = "scan-bad-address";             // not a P2PKH of this network, duplicate, 0 or > 16
inline constexpr const char* kWrongNetwork = "scan-wrong-network";         // the source serves another chain
inline constexpr const char* kTransport = "scan-transport";                // connect refused, timeout
inline constexpr const char* kRpcError = "scan-rpc-error";                 // dashd answered an error
inline constexpr const char* kBadReply = "scan-bad-reply";                 // a reply of the wrong shape
inline constexpr const char* kScanFailed = "scan-scantxoutset-failed";     // scantxoutset success:false
inline constexpr const char* kTipUnstable = "scan-tip-unstable";           // the tip kept moving during the scan
inline constexpr const char* kSourceInconsistent = "scan-source-inconsistent"; // the source contradicts itself (gettxout vs index)
inline constexpr const char* kForeignScript = "scan-foreign-script";       // a row pays a script that was not asked for
inline constexpr const char* kNodeUtxoNotFull = "scan-node-utxo-not-full"; // c2pool: no full UTXO set serving
inline constexpr const char* kNodeNoRoute = "scan-node-no-route";          // c2pool: no /api/utxo/scan (older node)
inline constexpr const char* kNodeRefused = "scan-node-refused";           // c2pool: 403 / busy / rate / other refusal
inline constexpr const char* kTruncated = "scan-truncated";                // c2pool: the reply hit its row limit
inline constexpr const char* kTipsDiffer = "scan-tips-differ";             // both: the two sources never met at one tip
inline constexpr const char* kSourceMismatch = "scan-source-mismatch";     // both: same tip, different rows
inline constexpr const char* kNothingToExport = "scan-nothing-to-export";  // no row left for an address
inline constexpr const char* kPlanRefused = "scan-plan-refused";           // the planner refused (DashAbort text kept)
inline constexpr const char* kUnsupported = "scan-unsupported";            // a plan shape this slice does not build
} // namespace cause

class ScanRefusal : public std::runtime_error {
public:
    ScanRefusal(std::string cause_name, const std::string& detail)
        : std::runtime_error(cause_name + ": " + detail), cause_(std::move(cause_name)) {}
    const std::string& cause() const noexcept { return cause_; }

private:
    std::string cause_;
};

struct Outpoint {
    std::string txid; // display order, lowercase
    uint32_t vout = 0;
};
bool operator<(const Outpoint& a, const Outpoint& b);
bool operator==(const Outpoint& a, const Outpoint& b);
std::string outpoint_str(const Outpoint& o); // "txid:vout"

struct ScanOptions {
    bool testnet = false;
    int dashd_tip_retries = 5;   // getaddressutxos: read until the tip did not move (export_utxos.py)
    int scantxoutset_retries = 2; // one scan, plus one retry when the tip moved under it
    int c2pool_tip_retries = 3;  // /api/utxo/scan answered tip_moved:true
};

struct ScanResult {
    std::string source;          // kSourceDashdIndex | kSourceDashdScan | kSourceC2pool | kSourceBoth
    int64_t tip_height = 0;
    std::string tip_hash;
    // One import per requested address, in request order (an address without
    // rows has an empty `utxos`). Each import: address, testnet, tip_height,
    // tip_hash, coinbase_flags = true, rows sorted (height, txid, vout).
    std::vector<c2w::dash::UtxoImport> imports;
    std::vector<Outpoint> mempool_spent; // sorted; never in `imports`
    bool cross_checked = false;  // both sources agreed at this tip
    std::string dashd_detail;    // e.g. "23.1.7 scantxoutset" (empty when dashd was not read)
    std::string c2pool_detail;   // e.g. "utxo full serving coins=4531254"
    int64_t elapsed_ms = 0;      // wall time; never written to a file
    std::string warning;         // e.g. "dashd has no address index; used scantxoutset"
};

struct UtxoSource {
    virtual ~UtxoSource() = default;
    virtual ScanResult scan(const std::vector<std::string>& addresses, const ScanOptions& opt) = 0;
    virtual const char* kind() const = 0; // "dashd" | "c2pool"
};

// ── helpers shared by the sources ───────────────────────────────────────────

// One raw row as a source reports it, before grouping.
struct RawRow {
    c2w::dash::Utxo utxo;        // txid lowercased, satoshis, height, script_pubkey_hex, coinbase
    std::string stated_address;  // the row's own address field, when the source has one
};

struct AddressScript {
    std::string address;
    std::string script_hex;      // the 25-byte P2PKH scriptPubKey, lowercase hex
};

// Validate the request: 1..16 distinct P2PKH addresses of the network.
// Throws ScanRefusal(kBadAddress).
std::vector<AddressScript> address_scripts(const std::vector<std::string>& addresses, bool testnet);

// Group `rows` by the address whose script each pays, in request order: a row
// paying a script that was not asked for, a stated address that disagrees with
// the script, an outpoint twice, a row above the tip or at height < 1, or a
// row without a coinbase flag is refused. Sets confirmations = tip - height + 1
// and sorts each group by (height, txid, vout).
std::vector<c2w::dash::UtxoImport> group_rows(const std::vector<RawRow>& rows,
                                              const std::vector<AddressScript>& scripts,
                                              int64_t tip_height, const std::string& tip_hash,
                                              bool testnet);

// DASH amount (a JSON float, as scantxoutset / gettxout print it) to duffs:
// round(x * 1e8), the rule tools/export_utxos.py and the README preflight use.
// false when x is not finite, negative or above MAX_MONEY.
bool dash_to_duffs(double x, int64_t& duffs);

bool is_hex64(const std::string& s);
std::string lower(std::string s);

} // namespace c2w::companion::scan
