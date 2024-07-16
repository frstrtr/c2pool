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
    //  INetwork:
    // void connected(std::shared_ptr<c2pool::Socket> socket) override { }
    void disconnect() override { }
    // BaseNode:
    c2pool::pool::PeerConnectionType handle_version(std::unique_ptr<c2pool::RawMessage> rmsg, peer_ptr peer) 
    { 
        std::cout << "version msg" << std::endl;
        return c2pool::pool::PeerConnectionType::legacy; 
    }

    NodeImpl() {}
    NodeImpl(boost::asio::io_context* ctx, const std::vector<std::byte>& prefix) : c2pool::pool::BaseNode<PeerImpl>(ctx, prefix) {}
};

class C2Pool : public c2pool::pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<c2pool::RawMessage> rmsg, NodeImpl::peer_ptr peer) override { std::cout << "c2pool msg " << rmsg->m_command << std::endl;}
};

class P2Pool : public c2pool::pool::Protocol<NodeImpl>
{
public:
    void handle_message(std::unique_ptr<c2pool::RawMessage> rmsg, NodeImpl::peer_ptr peer) override { std::cout << "p2pool msg " << rmsg->m_command << std::endl; }
};

using Node = c2pool::pool::NodeBridge<NodeImpl, P2Pool, C2Pool>;


int main(int argc, char *argv[])
{
#ifdef _WIN32
    setlocale(LC_ALL, "Russian");
    SetConsoleOutputCP(866);
#endif

    boost::asio::io_context* context = new boost::asio::io_context();
    std::vector<std::byte> prefix = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

    c2pool::log::Logger::init();
    // auto settings = c2pool::Fileconfig::load_file<c2pool::Settings>();


    Node* node = new Node(context, prefix);
    node->run(5555);
    context->run();
}

struct TestSocket
{
    std::unique_ptr<boost::asio::ip::tcp::socket> m_socket;

    TestSocket(std::unique_ptr<boost::asio::ip::tcp::socket> socket) : m_socket(std::move(socket))
    {

    }
};

// void listen(std::shared_ptr<TestSocket> m_socket, std::vector<std::byte>& prefix)
// {
//     boost::asio::async_read(*m_socket->m_socket, boost::asio::buffer(&prefix[0], prefix.size()),
//         [&](const auto& ec, std::size_t len)
//         {
//             std::cout << len << std::endl;
//             if (ec)
//             {
//                 std::cout << ec << " " << ec.message() << std::endl;
//                 return;
//             }

//              // if (c2pool::dev::compare_str(packet->value.prefix, net->PREFIX, length))
//             // if (packet->prefix == m_node->get_prefix())
//             {
//                 std::cout << "[" << prefix.size() << "] ";
//                 for (const auto& v : prefix) std::cout << (int) v << " ";
//                 std::cout << std::endl;
//             }
//             // else {}
//     			// TODO: m_node->error(libp2p::BAD_PEER, "[socket] prefix doesn't match");
//         }
//     );
// }

// int main()
// {
//     boost::asio::io_context* context = new boost::asio::io_context();
    
//     boost::asio::ip::tcp::acceptor acceptor(*context);
//     boost::asio::ip::tcp::endpoint listen_ep(boost::asio::ip::tcp::v4(), 5555);

//     acceptor.open(listen_ep.protocol());
// 	acceptor.set_option(boost::asio::socket_base::reuse_address(true));
// 	acceptor.bind(listen_ep);
// 	acceptor.listen();

//     std::shared_ptr<TestSocket> skt;
//     std::vector<std::byte> prefix;
//     prefix.resize(10);

//     acceptor.async_accept(
// 	    [&](boost::system::error_code ec, boost::asio::ip::tcp::socket io_socket)
// 	    {
// 	    	if (ec)
// 	    	{
//                 std::cout << ec << " " << ec.message() << std::endl;
// 	    		// if (ec != boost::system::errc::operation_canceled)
// 	    		// 	error(libp2p::ASIO_ERROR, "PoolListener::async_loop: " + ec.message(), NetAddress{socket_.remote_endpoint()});
// 	    		// else
// 	    		// 	LOG_DEBUG_POOL << "PoolListener::async_loop canceled";
// 	    		// return;
// 	    	}
// 	    		std::unique_ptr<boost::asio::ip::tcp::socket> tcp_socket = std::make_unique<boost::asio::ip::tcp::socket>(std::move(io_socket));
//                 skt = std::make_shared<TestSocket>(std::move(tcp_socket));
// 	    		// continue accept connections
// 	    		listen(skt, prefix);
// 		}
// 	);

//     context->run();
// }