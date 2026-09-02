// SPDX-License-Identifier: MIT
// PR-C4 wrapper — see c2pool_scriptcheck.h.
//
// Modelled on dashcore src/script/bitcoinconsensus.cpp (the shipped
// libdashconsensus entry point): deserialize the transaction once, then run
// VerifyScript with a TransactionSignatureChecker over the referenced coin's
// scriptPubKey. The tx bytes fed in are c2pool's own ::pack() output, which is
// dashd-wire-identical (it is the same serialization that produces accepted
// mainnet blocks); a byte that did not round-trip is caught by the
// GetSerializeSize == tx_to_len guard and returns 0 (fail-closed exclude).

#include "c2pool_scriptcheck.h"

#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <version.h>
#include <uint256.h>

#include <cstddef>
#include <cstring>
#include <exception>
#include <ios>

// Export marker for the pure-C entry points of this HIDDEN-VISIBILITY SHARED
// object (dash_scriptcheck .so/.dll — see src/impl/dash/CMakeLists.txt). On
// GCC/Clang, -fvisibility=hidden hides every bitcoin-derived symbol so it can
// never ODR-collide with c2pool's own btclibs copies at the final c2pool-dash
// link; __attribute__((visibility("default"))) re-exports just these entry
// points. MSVC rejects the GNU attribute (error C4430/C3861 on 'visibility')
// and hides all DLL symbols by default, so the equivalent is __declspec(
// dllexport) on exactly these entry points — WITHOUT it the c2pool_dash_*
// symbols stay unexported and c2pool-dash fails to link.
#if defined(_MSC_VER)
#  define C2POOL_DASH_SCRIPT_EXPORT __declspec(dllexport)
#else
#  define C2POOL_DASH_SCRIPT_EXPORT __attribute__((visibility("default")))
#endif

namespace {

// A stream that deserializes a single CTransaction one time (verbatim from
// dashcore bitcoinconsensus.cpp — keeps the wire read consensus-exact).
class TxInputStream
{
public:
    TxInputStream(int nVersionIn, const unsigned char* txTo, size_t txToLen)
        : m_version(nVersionIn), m_data(txTo), m_remaining(txToLen) {}

    void read(Span<std::byte> dst)
    {
        if (dst.size() > m_remaining) throw std::ios_base::failure("end of data");
        if (dst.data() == nullptr) throw std::ios_base::failure("bad destination buffer");
        if (m_data == nullptr) throw std::ios_base::failure("bad source buffer");
        memcpy(dst.data(), m_data, dst.size());
        m_remaining -= dst.size();
        m_data += dst.size();
    }

    template <typename T>
    TxInputStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }

    int GetVersion() const { return m_version; }

private:
    const int m_version;
    const unsigned char* m_data;
    size_t m_remaining;
};

} // namespace

// Enforce the pure-C flag constants against dashcore's own SCRIPT_VERIFY_* so a
// silent drift in either header is a compile error, never a wrong verdict.
static_assert((unsigned)C2POOL_DASH_SCRIPT_VERIFY_P2SH == (unsigned)SCRIPT_VERIFY_P2SH, "P2SH bit");
static_assert((unsigned)C2POOL_DASH_SCRIPT_VERIFY_DERSIG == (unsigned)SCRIPT_VERIFY_DERSIG, "DERSIG bit");
static_assert((unsigned)C2POOL_DASH_SCRIPT_VERIFY_NULLDUMMY == (unsigned)SCRIPT_VERIFY_NULLDUMMY, "NULLDUMMY bit");
static_assert((unsigned)C2POOL_DASH_SCRIPT_VERIFY_CLTV == (unsigned)SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, "CLTV bit");
static_assert((unsigned)C2POOL_DASH_SCRIPT_VERIFY_CSV == (unsigned)SCRIPT_VERIFY_CHECKSEQUENCEVERIFY, "CSV bit");

extern "C" C2POOL_DASH_SCRIPT_EXPORT
int c2pool_dash_verify_input(const unsigned char* script_pubkey, unsigned int script_pubkey_len,
                             const unsigned char* tx_to,         unsigned int tx_to_len,
                             unsigned int nIn, unsigned int flags)
{
    try {
        TxInputStream stream(PROTOCOL_VERSION, tx_to, tx_to_len);
        CTransaction tx(deserialize, stream);
        if (nIn >= tx.vin.size()) return 0;
        if (GetSerializeSize(tx, PROTOCOL_VERSION) != tx_to_len) return 0;
        CAmount am(0);
        PrecomputedTransactionData txdata(tx);
        return VerifyScript(
                   tx.vin[nIn].scriptSig,
                   CScript(script_pubkey, script_pubkey + script_pubkey_len),
                   flags,
                   TransactionSignatureChecker(&tx, nIn, am, txdata, MissingDataBehavior::FAIL),
                   nullptr)
               ? 1 : 0;
    } catch (const std::exception&) {
        return 0; // deserialization / any error => fail-closed exclude
    }
}

extern "C" C2POOL_DASH_SCRIPT_EXPORT
int c2pool_dash_legacy_sighash(const unsigned char* tx_to, unsigned int tx_to_len,
                               unsigned int nIn,
                               const unsigned char* script_code, unsigned int script_code_len,
                               int hash_type, unsigned char* out32)
{
    try {
        TxInputStream stream(PROTOCOL_VERSION, tx_to, tx_to_len);
        CTransaction tx(deserialize, stream);
        if (nIn >= tx.vin.size()) return 0;
        CAmount am(0);
        uint256 h = SignatureHash(
            CScript(script_code, script_code + script_code_len),
            tx, nIn, hash_type, am, SigVersion::BASE, nullptr);
        memcpy(out32, h.begin(), 32);
        return 1;
    } catch (const std::exception&) {
        return 0;
    }
}

// KAT helper: Hash160 = RIPEMD160(SHA256(data)), dashcore CHash160. Lets the
// self-signing KAT build a P2PKH scriptPubKey with no extra crypto dependency.
// Test-only; never on the serve path.
extern "C" C2POOL_DASH_SCRIPT_EXPORT
void c2pool_dash_hash160(const unsigned char* data, unsigned int len, unsigned char* out20)
{
    uint160 h = Hash160(Span<const unsigned char>(data, len));
    memcpy(out20, h.begin(), 20);
}
