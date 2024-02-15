#pragma once

#include <memory>

#include <libdevcore/exceptions.h>
#include <libp2p/preset/p2p_socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>

#include <boost/asio.hpp>

class CoindSocket : public BaseSocket<DebugMessages>
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;
	coind::ParentNetwork* net;

    void init_addr() override
    {
        boost::system::error_code ec;

        // global
        auto ep = socket->remote_endpoint(ec);
        // TODO: log ec;
        addr = {ep.address().to_string(), std::to_string(ep.port())};

        // local
        ep = socket->local_endpoint(ec);
        // TODO: log ec;
        addr_local = {ep.address().to_string(), std::to_string(ep.port())};
    }
public:

    CoindSocket(auto socket_, auto net_) : BaseSocket(), socket(std::move(socket_)), net(net_)
	{ 
        
    }

	void write(std::shared_ptr<Message> msg) override
	{
        std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>(msg, net->PREFIX, net->PREFIX_LENGTH);
        LOG_DEBUG_COIND << "\tCoind socket write msg: " << msg->command << ", Message data: \n" << *_msg;

        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
                                [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
                                {
                                    LOG_DEBUG_COIND << "[CoindSocket] peer receive message_" << cmd;
                                    if (_ec)
                                    {
                                        throw make_except<coind_exception, NodeExcept>((boost::format("[socket] write error (%1%: %2%)") % _ec % _ec.message()).str());
                                    } else
                                    {
                                        event_peer_receive->happened(cmd);
                                    }
                                });
        event_send_message->happened(msg->command);
	}

	// Read
	void read_prefix(std::shared_ptr<ReadSocketData> msg);
	void read_command(std::shared_ptr<ReadSocketData> msg);
	void read_length(std::shared_ptr<ReadSocketData> msg);
	void read_checksum(std::shared_ptr<ReadSocketData> msg);
	void read_payload(std::shared_ptr<ReadSocketData> msg);
	void final_read_message(std::shared_ptr<ReadSocketData> msg);

	void read() override
	{
		std::shared_ptr<ReadSocketData> msg = std::make_shared<ReadSocketData>(net->PREFIX_LENGTH);
		read_prefix(msg);
	}

	bool is_connected() override
	{
		return socket && socket->is_open();
	}

	void close() override
	{
        LOG_WARNING << "Coind socket has been disconnected from " << get_addr().to_string() << ".";
        LOG_INFO << messages_stat();

		socket->close();
        event_disconnect->happened();
	}
};