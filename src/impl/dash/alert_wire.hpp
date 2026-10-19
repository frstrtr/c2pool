// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// D-MINER.7: conversions between the wire messages (messages.hpp) and the
// policy-layer frames (alert_relay.hpp). Kept separate so alert_relay.hpp /
// alert_service.hpp stay free of the message/sharechain headers.

#include "alert_relay.hpp"
#include "messages.hpp"

#include <memory>

namespace dash::alert {

inline AlertFrame to_frame(const dash::message_alert& m)
{
    AlertFrame f;
    f.version = m.m_version;
    f.hops_left = m.m_hops_left;
    f.timestamp = m.m_timestamp;
    f.nonce = m.m_nonce;
    f.origin_pubkey = m.m_origin_pubkey;
    f.to_key_id = m.m_to_key_id;
    f.body = m.m_body;
    f.signature = m.m_signature;
    return f;
}

inline AckFrame to_frame(const dash::message_alertack& m)
{
    AckFrame a;
    a.version = m.m_version;
    a.origin_pubkey = m.m_origin_pubkey;
    a.nonce = m.m_nonce;
    a.status = m.m_status;
    a.relay_pubkey = m.m_relay_pubkey;
    a.signature = m.m_signature;
    return a;
}

inline std::unique_ptr<RawMessage> make_raw(const AlertFrame& f)
{
    return dash::message_alert::make_raw(f.version, f.hops_left, f.timestamp, f.nonce,
                                         f.origin_pubkey, f.to_key_id, f.body, f.signature);
}

inline std::unique_ptr<RawMessage> make_raw(const AckFrame& a)
{
    return dash::message_alertack::make_raw(a.version, a.origin_pubkey, a.nonce, a.status,
                                            a.relay_pubkey, a.signature);
}

} // namespace dash::alert
