#pragma once

#include <memory>
#include <queue>

#include <libp2p/preset/p2p_socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>
#include <libdevcore/logger.h>
#include <libdevcore/exceptions.h>

#include <boost/asio.hpp>

class PoolSocket : public Socket
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;
	c2pool::Network* net;

    void set_addr() override
    {
        boost::system::error_code ec;
        auto ep = socket->remote_endpoint(ec);
        addr = {ep.address().to_string(), std::to_string(ep.port())};
    }
public:

	PoolSocket(auto _socket, auto _net, auto conn_type) : Socket(conn_type), socket(std::move(_socket)), net(_net)
	{
		LOG_DEBUG_POOL << "PoolSocket created";
	}

	PoolSocket(auto _socket, auto _net, handler_type message_handler, auto conn_type) : Socket(std::move(message_handler), conn_type), socket(std::move(_socket)), net(_net)
	{
        LOG_DEBUG_POOL << "PoolSocket created2";
	}

	~PoolSocket()
    {
        LOG_DEBUG_POOL << "PoolSocket removed";
	}

	void write(std::shared_ptr<Message> msg) override
	{
        LOG_DEBUG_POOL << "Pool Socket write for " << msg->command << "!";

        std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>(msg, net->PREFIX, net->PREFIX_LENGTH);

        LOG_DEBUG_POOL << "\tMessage data: " << *_msg;

        if (_msg->len > 8000000)
        {
            LOG_INFO << "message length > max_payload_length!";
        }

        add_not_received(msg->command);
        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
                                 [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
                                 {
                                     LOG_DEBUG_POOL << "[PoolSocket] peer receive message_" << cmd;
                                     if (_ec)
                                     {
                                        throw make_except<pool_exception, NetExcept>((boost::format("[socket] write error (%1%: %2%)") % _ec % _ec.message()).str(), get_addr());
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
        LOG_WARNING << "Pool socket has been disconnected from " << get_addr().to_string() << ".";
        LOG_INFO.stream() << "Last message peer handle = " << last_message_sent << "; Last message received = " << last_message_received << "; not_received = " << not_received;

		socket->close();
        event_disconnect->happened();
	}
};