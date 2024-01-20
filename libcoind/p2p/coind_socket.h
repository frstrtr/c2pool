#pragma once

#include <memory>

#include <libp2p/preset/p2p_socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>

#include <boost/asio.hpp>

class CoindSocket : public Socket
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;
	coind::ParentNetwork* net;

    void set_addr() override
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

    CoindSocket(auto _socket, auto _net) : Socket(), socket(std::move(_socket)), net(_net)
	{ }

    CoindSocket(auto _socket, auto _net, handler_type message_handler) : Socket(std::move(message_handler)), socket(std::move(_socket)), net(_net)
	{ }

// Write

	void write(std::shared_ptr<Message> msg) override
	{
        LOG_DEBUG_COIND << "Coind socket write msg: " << msg->command;
        std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>(msg, net->PREFIX, net->PREFIX_LENGTH);

        LOG_DEBUG_COIND << "\tMessage data: " << *_msg;

        add_not_received(msg->command);
        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
                                 [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
                                 {
                                     LOG_DEBUG_COIND << "[CoindSocket] peer receive message_" << cmd;
                                     if (_ec)
                                     {
                                         disconnect((boost::format("write error (%1%: %2%)") % _ec % _ec.message()).str());
                                     } else
                                     {
                                         last_message_sent = cmd;
                                         remove_not_received(cmd);
                                     }
                                 });
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

	bool isConnected() override
	{
		return socket && socket->is_open();
	}

	void disconnect(const std::string& reason) override
	{
        if (!reason.empty())
        {
            auto [_addr, _port] = get_addr();
            LOG_WARNING << "Coind socket has been disconnected from " << _addr << ":" << _port << ", for a reason: " << reason;
            LOG_INFO.stream() << "Last message peer handle = " << last_message_sent << "; Last message received = " << last_message_received << "; not_received = " << not_received;
        }
        event_disconnect->happened();
		socket->close();
	}
};