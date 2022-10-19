#pragma once

#include <memory>

#include <libp2p/preset/p2p_socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>

#include <boost/asio.hpp>

class PoolSocket : public Socket
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;

	std::shared_ptr<c2pool::Network> net;
public:

	PoolSocket(auto _socket, auto _net) : socket(std::move(_socket)), net(std::move(_net))
	{
		LOG_TRACE << "socket created";
	}

	PoolSocket(auto _socket, auto _net, handler_type message_handler) : Socket(std::move(message_handler)), socket(std::move(_socket)), net(std::move(_net))
	{
		LOG_TRACE << "socket created";
	}

	~PoolSocket(){
		LOG_TRACE << "socket removed";
	}

	// Write
	void write_prefix(std::shared_ptr<Message> msg);
	void write_message_data(std::shared_ptr<Message> msg);

	void write(std::shared_ptr<Message> msg) override
	{
        LOG_DEBUG << "Pool Socket write for " << msg->command << "!";
//        boost::asio::post(socket->get_executor(),[&, _msg = msg](){
//            write_prefix(_msg);
//        });
        auto* _t = new boost::asio::steady_timer(socket->get_executor());
        _t->expires_from_now(std::chrono::seconds(1));
        _t->async_wait([&, _msg = msg](const auto& ec){
            LOG_INFO << "Writed!!!";
            write_prefix(_msg);
        });

//        write_prefix(msg);
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