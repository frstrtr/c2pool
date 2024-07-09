#include <iostream>
#include <memory>

#include <core/log.hpp>
#include <core/settings.hpp>
#include <core/fileconfig.hpp>

#include <core/uint256.hpp>

#include <pool/peer.hpp>
#include <pool/node.hpp>
#include <core/message.hpp>
#include <core/node_interface.hpp>

class PeerImpl
{
    int i;
};

class NodeImpl : public c2pool::pool::BaseNode<PeerImpl>
{
public:
    //  Communicator:
        void error(const message_error_type& err) override {}
    //  INetwork:
        void connected(std::shared_ptr<c2pool::Socket> socket) override { }
        void disconnect() override { }
    // BaseNode:
        void handle_version(std::unique_ptr<c2pool::RawMessage> rmsg, const peer_t& peer) { }

    NodeImpl() {}
    NodeImpl(boost::asio::io_context* ctx, const std::vector<std::byte>& prefix) : c2pool::pool::BaseNode<PeerImpl>(ctx, prefix) {}
};

class C2Pool : public c2pool::pool::Protocol<NodeImpl>
{
public:
    void handle_message() override {}
};

class P2Pool : public c2pool::pool::Protocol<NodeImpl>
{
public:
    void handle_message() override {}
};

using Node = c2pool::pool::NodeBridge<NodeImpl, P2Pool, C2Pool>;


int main(int argc, char *argv[])
{
    boost::asio::io_context* context = new boost::asio::io_context();
    std::vector<std::byte> prefix = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

    c2pool::log::Logger::init();
    auto settings = c2pool::Fileconfig::load_file<c2pool::Settings>();


    Node* node = new Node(context, prefix);
    node->run(5555);
    context->run();
}