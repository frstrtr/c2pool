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
        LOG_TRACE << "Coind socket write msg: " << msg->command;
//		write_prefix(msg);
        std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>(msg, net->PREFIX, net->PREFIX_LENGTH);

        std::cout << "write_message_data: ";
        for (auto v = _msg->data; v != _msg->data+_msg->len; v++)
        {
            std::cout << (unsigned int)((unsigned char) *v) << " ";
        }
        std::cout << std::endl;

        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
                                 [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
                                 {
                                     LOG_DEBUG << "PoolSocket: Write msg data called: " << cmd;
                                     if (_ec)
                                     {
                                         LOG_ERROR << "PoolSocket::write(): " << _ec << ":" << _ec.message();
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
        auto [addr, port] = get_addr();
        LOG_INFO << "Coind socket disconnected from " << addr << ":" << port;
		// TODO: call event disconnect
		socket->close();
	}

	tuple<std::string, std::string> get_addr() override
	{
		boost::system::error_code ec;
		auto ep = socket->remote_endpoint(ec);
		// TODO: log ec;
		return {ep.address().to_string(), std::to_string(ep.port())};
	}

};