#pragma once

#include <memory>
#include <queue>

#include <libp2p/preset/p2p_socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>

#include <boost/asio.hpp>

class PoolSocket : public Socket
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;

    std::queue<std::shared_ptr<Message>> messages_pool;
    std::shared_ptr<boost::asio::steady_timer> pool_timer;

	std::shared_ptr<c2pool::Network> net;
public:

	PoolSocket(auto _socket, auto _net) : socket(std::move(_socket)), net(std::move(_net))
	{
		LOG_TRACE << "socket created";
        pool_timer = std::make_shared<boost::asio::steady_timer>(socket->get_executor());
        pool_message_cycle();
	}

	PoolSocket(auto _socket, auto _net, handler_type message_handler) : Socket(std::move(message_handler)), socket(std::move(_socket)), net(std::move(_net))
	{
		LOG_TRACE << "socket created";
        pool_timer = std::make_shared<boost::asio::steady_timer>(socket->get_executor());
        pool_message_cycle();
	}

	~PoolSocket(){
		LOG_TRACE << "socket removed";
	}

    void pool_message_cycle()
    {
        pool_timer->expires_from_now(std::chrono::milliseconds(100));
        pool_timer->async_wait([&](const auto &ec)
                               {
                                   if (!ec)
                                   {
                                       if (!messages_pool.empty())
                                       {
                                           write_prefix(messages_pool.front());
                                           messages_pool.pop();
                                       }
                                       pool_message_cycle();
                                   } else
                                   {
                                       LOG_WARNING << "pool_message_cycle error!";
                                   }
                               });
    }

	// Write
	void write_prefix(std::shared_ptr<Message> msg);
	void write_message_data(std::shared_ptr<Message> msg);

	void write(std::shared_ptr<Message> msg) override
	{
        LOG_DEBUG << "Pool Socket write for " << msg->command << "!";

        messages_pool.push(std::move(msg));
//        pool_timer->expires_from_now(std::chrono::milliseconds(100));
//        pool_timer->async_wait([&, _msg = msg](const auto& ec){
//            LOG_INFO << "Writed!!!";
//            write_prefix(_msg);
//        });

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