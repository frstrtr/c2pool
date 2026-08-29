// dashd ZMQ `hashblock` instant tip-notify -- implementation.
// See zmq_tip_notify.hpp for the contract. libzmq usage is guarded by
// C2POOL_ZMQ; the pure hex helper is always compiled so the KAT can pin the
// frame-decode contract without libzmq.

#include "zmq_tip_notify.hpp"

// NOTE: all #includes MUST be at file scope, never inside the namespace below.
#ifdef C2POOL_ZMQ
#include <zmq.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <utility>
#endif

namespace dash::coin {

std::string zmq_hashblock_frame_to_hex(const unsigned char* body, unsigned long len)
{
    if (!body || len != 32)
        return {};
    static const char* const hexd = "0123456789abcdef";
    std::string out;
    out.resize(64);
    // dashd publishes the hash ALREADY in RPC/display (reversed) byte order:
    // CZMQPublishHashBlockNotifier::NotifyBlock writes data[31-i]=hash.begin()[i]
    // before SendZmqMessage, i.e. it reverses the internal little-endian array
    // for us (Bitcoin Core doc/zmq.md: hashes are published "in reversed byte
    // order, the same format as the RPC interface"). So the wire frame
    // hex-encodes DIRECTLY to the getbestblockhash string -- do NOT reverse
    // again, or the ZMQ hash never matches the poll's and the shared
    // TipHashDedup never coalesces the poll+ZMQ double-fire.
    for (unsigned i = 0; i < 32; ++i) {
        const unsigned char b = body[i];
        out[i * 2]     = hexd[b >> 4];
        out[i * 2 + 1] = hexd[b & 0x0f];
    }
    return out;
}

#ifdef C2POOL_ZMQ

ZmqHashblockSubscriber::ZmqHashblockSubscriber(
    std::string endpoint, std::function<void(const std::string&)> on_new_tip)
    : endpoint_(std::move(endpoint)), on_new_tip_(std::move(on_new_tip))
{
}

ZmqHashblockSubscriber::~ZmqHashblockSubscriber()
{
    stop();
}

void ZmqHashblockSubscriber::start()
{
    if (running_.load() || thread_.joinable())
        return;
    ctx_ = zmq_ctx_new();
    if (!ctx_) {
        std::cout << "[Stratum] zmq hashblock: zmq_ctx_new failed; "
                     "falling back to the 3 s poll only\n";
        return;
    }
    stop_.store(false);
    thread_ = std::thread([this] { run_loop(); });
}

void ZmqHashblockSubscriber::stop()
{
    stop_.store(true);
    if (thread_.joinable())
        thread_.join();
    if (ctx_) {
        zmq_ctx_term(ctx_);
        ctx_ = nullptr;
    }
}

void ZmqHashblockSubscriber::run_loop()
{
    running_.store(true);
    while (!stop_.load()) {
        void* sub = zmq_socket(ctx_, ZMQ_SUB);
        if (!sub) {
            // Cannot create a socket -- back off and retry (never spin).
            for (int i = 0; i < 20 && !stop_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        int rcv_timeout_ms = 500;   // so the loop re-checks stop_ ~2x/s
        zmq_setsockopt(sub, ZMQ_RCVTIMEO, &rcv_timeout_ms, sizeof rcv_timeout_ms);
        int linger = 0;
        zmq_setsockopt(sub, ZMQ_LINGER, &linger, sizeof linger);
        zmq_setsockopt(sub, ZMQ_SUBSCRIBE, "hashblock", 9);

        if (zmq_connect(sub, endpoint_.c_str()) != 0) {
            std::cout << "[Stratum] zmq hashblock: connect to " << endpoint_
                      << " failed (" << zmq_strerror(zmq_errno())
                      << "); the 3 s poll remains the active path; retrying\n";
            zmq_close(sub);
            for (int i = 0; i < 20 && !stop_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        std::cout << "[Stratum] zmq hashblock: subscribed at " << endpoint_
                  << " (primary instant tip-notify; 3 s poll is the backstop)\n";

        // Receive loop. dashd hashblock messages are multipart:
        //   [0] topic  "hashblock"
        //   [1] body   32-byte block hash (little-endian internal order)
        //   [2] seq    4-byte LE sequence (drained, unused)
        while (!stop_.load()) {
            zmq_msg_t topic;
            zmq_msg_init(&topic);
            int r = zmq_msg_recv(&topic, sub, 0);
            if (r < 0) {
                zmq_msg_close(&topic);
                if (zmq_errno() == EAGAIN)
                    continue;             // timeout: re-check stop_ and retry
                break;                    // real transport error: reconnect
            }
            std::string hex;
            int more = 0;
            size_t more_sz = sizeof more;
            zmq_getsockopt(sub, ZMQ_RCVMORE, &more, &more_sz);
            if (more) {
                zmq_msg_t body;
                zmq_msg_init(&body);
                if (zmq_msg_recv(&body, sub, 0) >= 0) {
                    hex = zmq_hashblock_frame_to_hex(
                        static_cast<const unsigned char*>(zmq_msg_data(&body)),
                        zmq_msg_size(&body));
                }
                zmq_msg_close(&body);
            }
            zmq_msg_close(&topic);
            // Drain any trailing frames (sequence number etc).
            more = 0;
            more_sz = sizeof more;
            zmq_getsockopt(sub, ZMQ_RCVMORE, &more, &more_sz);
            while (more && !stop_.load()) {
                zmq_msg_t drop;
                zmq_msg_init(&drop);
                zmq_msg_recv(&drop, sub, 0);
                zmq_msg_close(&drop);
                more = 0;
                more_sz = sizeof more;
                zmq_getsockopt(sub, ZMQ_RCVMORE, &more, &more_sz);
            }
            if (!hex.empty() && on_new_tip_) {
                try {
                    on_new_tip_(hex);
                } catch (...) {
                    // never let a callback throw kill the subscriber thread
                }
            }
        }
        zmq_close(sub);
        // Bounded backoff before reconnect on a broken stream.
        for (int i = 0; i < 20 && !stop_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    running_.store(false);
}

#endif // C2POOL_ZMQ

} // namespace dash::coin
