#include <iostream>
#include <memory>

#include <core/log.hpp>
#include <core/settings.hpp>
#include <core/fileconfig.hpp>

#include <core/uint256.hpp>

#include <pool/node.hpp>
#include <core/message.hpp>
#include <core/node_interface.hpp>


class NodeImpl : public c2pool::INode
{
public:
    void handle(std::unique_ptr<c2pool::RawMessage> msg) const override
    {}

    void error(const message_error_type& err) override
    {}

    void connected() override
    {}

    void disconnect() override
    {}

    NodeImpl() {}
    NodeImpl(boost::asio::io_context* ctx, const std::vector<std::byte>& prefix) : INode(ctx, prefix) {}
};

class C2Pool : public c2pool::pool::IProtocol<NodeImpl>
{
public:
    void handle_message() override {}
};

class P2Pool : public c2pool::pool::IProtocol<NodeImpl>
{
public:
    void handle_message() override {}
};

using Node = c2pool::pool::BaseNode<NodeImpl, P2Pool, C2Pool>;


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