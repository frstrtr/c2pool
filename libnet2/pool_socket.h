#pragma once

#include <memory>
#include <queue>

#include <libp2p/preset/p2p_socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>
#include <libdevcore/logger.h>

#include <boost/asio.hpp>

class PoolSocket : public Socket
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;
	std::shared_ptr<c2pool::Network> net;

    void set_addr() override
    {
        boost::system::error_code ec;
        auto ep = socket->remote_endpoint(ec);
//        LOG_INFO << socket->local_endpoint(ec).address().to_string();
        // TODO: log ec;
        addr = {ep.address().to_string(), std::to_string(ep.port())};
    }
public:

	PoolSocket(auto _socket, auto _net) : socket(std::move(_socket)), net(std::move(_net))
	{
		LOG_TRACE << "socket created";
	}

	PoolSocket(auto _socket, auto _net, handler_type message_handler) : Socket(std::move(message_handler)), socket(std::move(_socket)), net(std::move(_net))
	{
		LOG_TRACE << "socket created2";
	}

	~PoolSocket(){
		LOG_TRACE << "socket removed";
	}

	// Write
//	void write_prefix(std::shared_ptr<Message> msg);
//	void write_message_data(std::shared_ptr<Message> msg);

	void write(std::shared_ptr<Message> msg) override
	{
        LOG_DEBUG << "Pool Socket write for " << msg->command << "!";
//        write_prefix(msg);

        std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>(msg, net->PREFIX, net->PREFIX_LENGTH);

        std::cout << "write_message_data: ";
        for (auto v = _msg->data; v != _msg->data+_msg->len; v++)
        {
            std::cout << (unsigned int)((unsigned char) *v) << " ";
        }
        std::cout << std::endl;

        LOG_DEBUG << "message length = " << _msg->len;
        if (_msg->len > 8000000)
        {
            LOG_INFO << "message length > max_payload_length!";
        }

        add_not_received(msg->command);
        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
                                 [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
                                 {
                                     LOG_DEBUG << "[PoolSocket] peer receive message_" << cmd;
                                     if (_ec)
                                     {
                                         std::string reason = "[PoolSocket] write error: " + _ec.message();
                                         bad_peer.happened(reason);
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
        LOG_INFO << "\tPool socket disconnected from " << _addr << ":" << _port;
        LOG_INFO.stream() << "\tLast message peer handle = " << last_message_sent << "; Last message received = " << last_message_received << "; not_received = " << not_received;
		socket->close();
	}
};