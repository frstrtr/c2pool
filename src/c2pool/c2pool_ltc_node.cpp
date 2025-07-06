#include <iostream>
#include <memory>
#include <chrono>
#include <thread>

// Core includes
#include <core/log.hpp>
#include <core/settings.hpp>
#include <core/uint256.hpp>
#include <pool/node.hpp>
#include <pool/protocol.hpp>

// LTC sharechain implementation
#include <impl/ltc/share.hpp>
#include <impl/ltc/node.hpp>
#include <impl/ltc/messages.hpp>
#include <impl/ltc/config.hpp>

#include <boost/asio.hpp>

namespace c2pool_ltc
{

// C2Pool-specific configuration extending LTC config
struct C2PoolConfig : public ltc::Config
{
    bool m_testnet = false;
    std::string m_name = "c2pool_sharechain";
    
    C2PoolConfig() : ltc::Config("ltc") {
        // Initialize with default LTC network settings but customize for c2pool
        m_name = "c2pool_sharechain";
        // Use c2pool-specific network prefixes
        pool()->m_prefix = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdc}}; // mainnet
    }
    
    void set_testnet(bool testnet) {
        m_testnet = testnet;
        if (testnet) {
            pool()->m_prefix = {std::byte{0xfc}, std::byte{0xc1}, std::byte{0xb7}, std::byte{0xdd}}; // testnet
            m_name = "c2pool_sharechain_testnet";
        }
    }
};

// C2Pool peer data extending LTC peer
struct C2PoolPeer : public ltc::Peer
{
    uint64_t m_shares_received = 0;
    uint64_t m_shares_sent = 0;
    uint64_t m_last_share_time = 0;
    
    void update_share_stats(bool sent = false) {
        if (sent) {
            m_shares_sent++;
        } else {
            m_shares_received++;
            m_last_share_time = std::time(nullptr);
        }
    }
};

// C2Pool sharechain using LTC share types
using C2PoolShareChain = ltc::ShareChain;

class C2PoolLTCNodeImpl : public ltc::NodeImpl
{
private:
    uint64_t m_local_shares_count = 0;
    uint64_t m_foreign_shares_count = 0;
    std::unique_ptr<ltc::Legacy> m_legacy_protocol;
    std::unique_ptr<ltc::Actual> m_actual_protocol;
    
public:
    using config_t = C2PoolConfig;
    using peer_t = pool::Peer<C2PoolPeer>;
    using peer_ptr = std::shared_ptr<peer_t>;
    
    C2PoolLTCNodeImpl() : ltc::NodeImpl() {
        initialize_protocols();
    }
    
    C2PoolLTCNodeImpl(boost::asio::io_context* ctx, config_t* config) : ltc::NodeImpl(ctx, config) {
        initialize_protocols();
    }
    
private:
    void initialize_protocols() {
        m_legacy_protocol = std::make_unique<ltc::Legacy>();
        m_actual_protocol = std::make_unique<ltc::Actual>();
    }
    
public:
    // Override NodeImpl methods to add c2pool-specific logging and handling
    void send_ping(peer_ptr peer) override {
        ltc::NodeImpl::send_ping(peer);
        
        // Get sharechain stats for logging
        uint64_t total_shares = get_total_shares();
        LOG_INFO << "Sending ping to c2pool peer: " << peer->addr().to_string() 
                 << " (shares in chain: " << total_shares << ")";
    }
    
    pool::PeerConnectionType handle_version(std::unique_ptr<RawMessage> rmsg, peer_ptr peer) override
    { 
        LOG_INFO << "Version message from c2pool peer: " << peer->addr().to_string();
        
        auto connection_type = ltc::NodeImpl::handle_version(std::move(rmsg), peer);
        
        // Log best share info
        if (m_chain && !m_chain->empty()) {
            LOG_INFO << "Our best share hash available for sync";
        }
        
        return connection_type;
    }
    
    // C2Pool-specific share handling methods
    void add_local_share(const ltc::ShareType& share) {
        if (!m_chain) {
            LOG_ERROR << "No sharechain available for adding local share";
            return;
        }
        
        bool was_added = false;
        share.USE([&](auto* typed_share) {
            uint256 hash = typed_share->m_hash;
            
            if (m_chain->contains(hash)) {
                LOG_WARNING << "Duplicate local share, ignoring: " << hash.ToString().substr(0, 16) << "...";
                return;
            }
            
            LOG_INFO << "Adding local share to sharechain: " << hash.ToString().substr(0, 16) << "...";
            
            // Add to sharechain using LTC infrastructure
            try {
                m_chain->add(typed_share);
                m_local_shares_count++;
                was_added = true;
                
                log_sharechain_stats();
                
                // Broadcast to all peers
                broadcast_new_share(hash);
            } catch (const std::exception& e) {
                LOG_ERROR << "Failed to add local share: " << e.what();
            }
        });
    }
    
    void handle_foreign_share(const ltc::ShareType& share, const NetService& peer_addr) {
        if (!m_chain) {
            LOG_ERROR << "No sharechain available for adding foreign share";
            return;
        }
        
        share.USE([&](auto* typed_share) {
            uint256 hash = typed_share->m_hash;
            
            if (m_chain->contains(hash)) {
                LOG_WARNING << "Duplicate foreign share from " << peer_addr.to_string() 
                           << ", ignoring: " << hash.ToString().substr(0, 16) << "...";
                return;
            }
            
            LOG_INFO << "Adding foreign share from " << peer_addr.to_string() 
                     << ": " << hash.ToString().substr(0, 16) << "...";
            
            try {
                // Set peer address
                typed_share->peer_addr = peer_addr;
                
                m_chain->add(typed_share);
                m_foreign_shares_count++;
                
                // Update peer statistics
                if (m_connections.find(peer_addr) != m_connections.end()) {
                    auto peer_data = std::static_pointer_cast<peer_t>(m_connections[peer_addr]);
                    peer_data->data.update_share_stats(false);
                }
                
                log_sharechain_stats();
            } catch (const std::exception& e) {
                LOG_ERROR << "Failed to add foreign share: " << e.what();
            }
        });
    }
    
    std::vector<ltc::ShareType> get_shares_for_sync(const std::vector<uint256>& hashes, uint64_t max_count = 1000) {
        if (!m_chain) {
            return {};
        }
        
        // Use LTC node's existing share retrieval logic
        return handle_get_share(hashes, max_count, {}, NetService{});
    }
    
    void broadcast_new_share(const uint256& share_hash) {
        // Use LTC protocol to send share data to all connected peers
        for (auto& [addr, peer] : m_connections) {
            auto peer_data = std::static_pointer_cast<peer_t>(peer);
            peer_data->data.update_share_stats(true);
            
            LOG_DEBUG << "Broadcasting share " << share_hash.ToString().substr(0, 16) 
                      << "... to " << addr.to_string();
            
            // TODO: Use actual LTC protocol message sending
            // This would typically send an ltc::message_shares to the peer
        }
    }
    
    uint64_t get_total_shares() const {
        if (!m_chain) return 0;
        return m_chain->get_height(m_chain->get_best_hash());
    }
    
    uint256 get_total_work() const {
        if (!m_chain) return uint256::ZERO;
        // Get total work from the best chain
        return m_chain->get_work(m_chain->get_best_hash());
    }
    
    uint256 get_best_share_hash() const {
        if (!m_chain) return uint256::ZERO;
        return m_chain->get_best_hash();
    }
    
    void log_sharechain_stats() {
        uint64_t total_shares = get_total_shares();
        uint256 total_work = get_total_work();
        uint256 best_hash = get_best_share_hash();
        
        LOG_INFO << "Sharechain stats:";
        LOG_INFO << "  Total shares: " << total_shares 
                 << " (local: " << m_local_shares_count 
                 << ", foreign: " << m_foreign_shares_count << ")";
        LOG_INFO << "  Total work: " << total_work.ToString().substr(0, 16) << "...";
        if (best_hash != uint256::ZERO) {
            LOG_INFO << "  Best share: " << best_hash.ToString().substr(0, 16) << "...";
        }
        LOG_INFO << "  Connected peers: " << m_connections.size();
    }
    
    // Demo method to add test shares for development
    void add_demo_shares() {
        LOG_INFO << "Adding demo shares to c2pool sharechain...";
        
        // Create a few test shares using LTC share types
        for (int i = 0; i < 5; ++i) {
            uint256 hash = uint256::FromHex(
                std::string(64 - std::to_string(i + 1000).length(), '0') + std::to_string(i + 1000)
            );
            uint256 prev_hash = (i == 0) ? uint256::ZERO : uint256::FromHex(
                std::string(64 - std::to_string(i + 999).length(), '0') + std::to_string(i + 999)
            );
            
            // Create an LTC Share for demo purposes
            auto share = ltc::ShareType::create<ltc::Share>(hash, prev_hash);
            share.USE([&](auto* typed_share) {
                typed_share->m_timestamp = std::time(nullptr) - i * 60; // Spaced 1 minute apart
                typed_share->m_subsidy = 25 * 100000000ULL; // 25 LTC in satoshis
                typed_share->m_bits = 0x1d00ffff; // Difficulty
                typed_share->m_nonce = 123456 + i;
                typed_share->peer_addr = NetService{}; // Local share
            });
            
            add_local_share(share);
        }
        
        LOG_INFO << "Demo shares added successfully";
    }
};

// C2Pool protocol handler using LTC message infrastructure
class C2PoolLTCProtocol : public pool::Protocol<C2PoolLTCNodeImpl>
{
public:
    void handle_message(std::unique_ptr<RawMessage> rmsg, C2PoolLTCNodeImpl::peer_ptr peer) override {
        LOG_INFO << "C2Pool LTC sharechain message [" << rmsg->m_command << "] from " << peer->addr().to_string();
        
        // Delegate to appropriate LTC protocol handler based on peer version/type
        if (rmsg->m_command == "shares") {
            handle_shares_message(std::move(rmsg), peer);
        } else if (rmsg->m_command == "sharereq") {
            handle_sharereq_message(std::move(rmsg), peer);
        } else if (rmsg->m_command == "sharereply") {
            handle_sharereply_message(std::move(rmsg), peer);
        } else if (rmsg->m_command == "bestblock") {
            handle_bestblock_message(std::move(rmsg), peer);
        } else {
            LOG_WARNING << "Unknown message type: " << rmsg->m_command;
        }
    }
    
private:
    void handle_shares_message(std::unique_ptr<RawMessage> rmsg, C2PoolLTCNodeImpl::peer_ptr peer) {
        try {
            // Parse LTC shares message
            ltc::message_shares msg;
            msg.UnserializeFromMessage(*rmsg);
            
            LOG_INFO << "Received " << msg.m_shares.size() << " shares from " << peer->addr().to_string();
            
            // Process each share
            for (const auto& raw_share : msg.m_shares) {
                try {
                    auto share = ltc::load_share(const_cast<chain::RawShare&>(raw_share), peer->addr());
                    
                    auto node = static_cast<C2PoolLTCNodeImpl*>(m_node);
                    node->handle_foreign_share(share, peer->addr());
                } catch (const std::exception& e) {
                    LOG_ERROR << "Failed to process share from " << peer->addr().to_string() << ": " << e.what();
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR << "Failed to parse shares message: " << e.what();
        }
    }
    
    void handle_sharereq_message(std::unique_ptr<RawMessage> rmsg, C2PoolLTCNodeImpl::peer_ptr peer) {
        try {
            ltc::message_sharereq msg;
            msg.UnserializeFromMessage(*rmsg);
            
            LOG_INFO << "Share request from " << peer->addr().to_string() 
                     << " for " << msg.m_hashes.size() << " hashes, " 
                     << msg.m_parents << " parents";
            
            auto node = static_cast<C2PoolLTCNodeImpl*>(m_node);
            auto shares = node->get_shares_for_sync(msg.m_hashes, msg.m_parents);
            
            // Send reply with shares
            ltc::message_sharereply reply;
            reply.m_id = msg.m_id;
            reply.m_result = ltc::ShareReplyResult::good;
            
            // Convert shares to raw format for transmission
            for (const auto& share : shares) {
                share.USE([&](auto* typed_share) {
                    chain::RawShare raw_share;
                    raw_share.type = share.m_type;
                    
                    // Serialize share to raw_share.contents
                    // TODO: Implement proper serialization using LTC formatter
                    reply.m_shares.push_back(raw_share);
                });
            }
            
            // Send reply message
            // TODO: Implement actual message sending via peer connection
            LOG_INFO << "Sending " << reply.m_shares.size() << " shares to " << peer->addr().to_string();
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Failed to handle share request: " << e.what();
        }
    }
    
    void handle_sharereply_message(std::unique_ptr<RawMessage> rmsg, C2PoolLTCNodeImpl::peer_ptr peer) {
        try {
            ltc::message_sharereply msg;
            msg.UnserializeFromMessage(*rmsg);
            
            if (msg.m_result == ltc::ShareReplyResult::good) {
                LOG_INFO << "Received share reply from " << peer->addr().to_string() 
                         << " with " << msg.m_shares.size() << " shares";
                
                // Process received shares
                for (const auto& raw_share : msg.m_shares) {
                    try {
                        auto share = ltc::load_share(const_cast<chain::RawShare&>(raw_share), peer->addr());
                        
                        auto node = static_cast<C2PoolLTCNodeImpl*>(m_node);
                        node->handle_foreign_share(share, peer->addr());
                    } catch (const std::exception& e) {
                        LOG_ERROR << "Failed to process share from reply: " << e.what();
                    }
                }
            } else {
                LOG_WARNING << "Share reply error from " << peer->addr().to_string() 
                           << ", result: " << static_cast<int>(msg.m_result);
            }
        } catch (const std::exception& e) {
            LOG_ERROR << "Failed to handle share reply: " << e.what();
        }
    }
    
    void handle_bestblock_message(std::unique_ptr<RawMessage> rmsg, C2PoolLTCNodeImpl::peer_ptr peer) {
        try {
            ltc::message_bestblock msg;
            msg.UnserializeFromMessage(*rmsg);
            
            LOG_INFO << "Best block update from " << peer->addr().to_string() 
                     << ": " << msg.m_hash.ToString().substr(0, 16) << "...";
            
            // Update peer's best block info
            peer->data.m_best_share = msg.m_hash;
            
        } catch (const std::exception& e) {
            LOG_ERROR << "Failed to handle bestblock message: " << e.what();
        }
    }
};

} // namespace c2pool_ltc

// Demo function to test the LTC-based c2pool node
void test_c2pool_ltc_node()
{
    LOG_INFO << "Testing C2Pool LTC-based sharechain node...";
    
    boost::asio::io_context io_context;
    
    // Create configuration
    auto config = std::make_unique<c2pool_ltc::C2PoolConfig>();
    config->set_testnet(true); // Use testnet for testing
    
    // Create node
    auto node = std::make_unique<c2pool_ltc::C2PoolLTCNodeImpl>(&io_context, config.get());
    
    // Add demo shares
    node->add_demo_shares();
    
    // Log final stats
    node->log_sharechain_stats();
    
    LOG_INFO << "C2Pool LTC node test completed";
}
