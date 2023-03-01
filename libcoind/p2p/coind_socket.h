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
	std::shared_ptr<coind::ParentNetwork> net;

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

    CoindSocket(auto _socket, auto _net) : Socket(), socket(std::move(_socket)), net(std::move(_net))
	{
	}

    CoindSocket(auto _socket, auto _net, handler_type message_handler) : Socket(std::move(message_handler)), socket(std::move(_socket)), net(std::move(_net))
	{
	}

//	// Write
//	void write_prefix(std::shared_ptr<Message> msg);
//	void write_message_data(std::shared_ptr<Message> msg);

	void write(std::shared_ptr<Message> msg) override
	{
        LOG_DEBUG_COIND << "Coind socket write msg: " << msg->command;
//		write_prefix(msg);
        std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>(msg, net->PREFIX, net->PREFIX_LENGTH);

        LOG_DEBUG_COIND << "\tMessage data: " << *_msg;

        add_not_received(msg->command);
        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
                                 [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
                                 {
                                     LOG_DEBUG_COIND << "[CoindSocket] peer receive message_" << cmd;
                                     if (_ec)
                                     {
                                         LOG_ERROR << "[CoindSocket] write error: " << _ec << ":" << _ec.message();
                                         disconnect();
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
		return socket->is_open();
	}

	void disconnect() override
	{
        auto [_addr, _port] = get_addr();
        LOG_INFO << "Coind socket disconnected from " << _addr << ":" << _port;
        LOG_INFO.stream() << "Last message peer handle = " << last_message_sent << "; Last message received = " << last_message_received << "; not_received = " << not_received;
		// TODO: call event disconnect
		socket->close();
	}
};