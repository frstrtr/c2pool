#pragma once
// dashd ZMQ `hashblock` instant tip-notify for the DASH fallback arm.
//
// This is a HARDENING on top of the #770 fallback-arm 3 s getbestblockhash
// poll: dashd publishes a `hashblock` ZMQ message the instant a new block
// connects, so a SUB subscriber closes the lost-block window from <=3 s
// (poll) to ~0 s. On a new tip it fires the SAME refresh trio the poll fires
// (invalidate_template_cache + bump_work_generation + notify_all), and it
// shares the poll's last-seen-tip dedup so a ZMQ notify and a poll tick on the
// same tip coalesce to a single refresh.
//
// OPT-IN + optional: the subscriber is only constructed when the operator
// passes --coin-zmq-hashblock ENDPOINT. libzmq itself is an OPTIONAL build
// dependency guarded by C2POOL_ZMQ; when libzmq is absent the class is not
// declared and c2pool-dash builds + runs exactly as the poll-only #770 branch.
//
// CONSENSUS-NEUTRAL: template-refresh / stratum-notify path only. No
// difficulty retarget, share-selection, reward-split, or block-acceptance code
// is touched.

#include <functional>
#include <string>

#ifdef C2POOL_ZMQ
#include <atomic>
#include <thread>
#endif

namespace dash::coin {

// Pure dedup helper -- testable without libzmq. Returns true iff `hash_hex`
// is a NEW tip (non-empty AND != the last observed). The fallback-arm poll and
// the ZMQ subscriber share ONE instance so a double-fire on the same tip (both
// paths racing on the same block) resolves to a single refresh trio.
class TipHashDedup
{
public:
    bool is_new_tip(const std::string& hash_hex)
    {
        if (hash_hex.empty() || hash_hex == last_)
            return false;
        last_ = hash_hex;
        return true;
    }
    const std::string& last() const { return last_; }
    void set_last(const std::string& h) { last_ = h; }

private:
    std::string last_;
};

// Convert a raw dashd ZMQ `hashblock` body (the 32-byte block hash) to the hex
// string that getbestblockhash reports. dashd publishes the hash ALREADY in
// RPC/display (reversed) byte order -- CZMQPublishHashBlockNotifier::NotifyBlock
// reverses the internal little-endian array before sending -- so this helper
// hex-encodes the frame DIRECTLY (NO further reversal). That is what makes a ZMQ
// notify and a poll tick produce the SAME hash string, so they dedup against
// each other. Returns "" if len != 32 or body is null. Pure; no libzmq needed.
std::string zmq_hashblock_frame_to_hex(const unsigned char* body, unsigned long len);

#ifdef C2POOL_ZMQ
// dashd ZMQ `hashblock` SUB subscriber. Owns a background thread that dials
// `endpoint` (e.g. tcp://127.0.0.1:28332), subscribes to the "hashblock"
// topic, and invokes `on_new_tip(hash_hex)` for every block-hash frame. The
// callback runs on the subscriber thread -- the caller is responsible for
// hopping onto its run-loop thread (e.g. boost::asio::post) before touching
// work_source / stratum state.
//
// Never throws into the caller. A down/unreachable endpoint does NOT crash or
// block the node: the recv loop uses a receive timeout, and transport errors
// trigger a bounded reconnect backoff. stop() joins the thread.
class ZmqHashblockSubscriber
{
public:
    ZmqHashblockSubscriber(std::string endpoint,
                           std::function<void(const std::string&)> on_new_tip);
    ~ZmqHashblockSubscriber();

    ZmqHashblockSubscriber(const ZmqHashblockSubscriber&) = delete;
    ZmqHashblockSubscriber& operator=(const ZmqHashblockSubscriber&) = delete;

    // Spawn the subscriber thread. Idempotent-safe to call once.
    void start();
    // Signal the thread to stop and join it; tears down the ZMQ context.
    void stop();

    bool running() const { return running_.load(); }
    const std::string& endpoint() const { return endpoint_; }

private:
    void run_loop();

    std::string endpoint_;
    std::function<void(const std::string&)> on_new_tip_;
    void* ctx_ = nullptr;   // zmq context (void* -- keeps zmq.h out of the header)
    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> running_{false};
};
#endif // C2POOL_ZMQ

} // namespace dash::coin
