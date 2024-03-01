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

typedef BaseSocket<DebugMessages> BasePoolSocket;

class PoolSocket : public BasePoolSocket
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;
	c2pool::Network* net;	

    void init_addr() override
    {
        boost::system::error_code ec;
        auto ep = socket->remote_endpoint(ec);
        addr = {ep.address().to_string(), std::to_string(ep.port())};
    }

	void read_prefix(std::shared_ptr<ReadSocketData> msg);
	void read_command(std::shared_ptr<ReadSocketData> msg);
	void read_length(std::shared_ptr<ReadSocketData> msg);
	void read_checksum(std::shared_ptr<ReadSocketData> msg);
	void read_payload(std::shared_ptr<ReadSocketData> msg);
	void final_read_message(std::shared_ptr<ReadSocketData> msg);
public:

	PoolSocket(auto socket_, auto net_, connection_type type_, error_handler_type error_handler_) 
		: BasePoolSocket(type_, error_handler_, DebugMessages::config{}), socket(socket_), net(net_)
	{
		init_addr();
		LOG_DEBUG_POOL << "PoolSocket created";
	}

	~PoolSocket()
    {
        LOG_DEBUG_POOL << "PoolSocket " << get_addr().to_string() << " removed";
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

        event_send_message->happened(msg->command);
        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
                                 [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
                                 {
                                     LOG_DEBUG_POOL << "[PoolSocket] peer receive message_" << cmd;
                                     if (_ec)
                                     {
                                        throw make_except<pool_exception, NetExcept>((boost::format("[socket] write error (%1%: %2%)") % _ec % _ec.message()).str(), get_addr());
                                     } else
                                     {
                                        event_peer_receive->happened(cmd);
                                     }
                                 });
	}

	// Read
	void read() override
	{
		std::shared_ptr<ReadSocketData> msg = std::make_shared<ReadSocketData>(net->PREFIX_LENGTH);
		read_prefix(msg);
	}

	bool is_connected() override
	{
		return socket->is_open();
	}

	void close() override
	{
        LOG_WARNING << "Pool socket has been disconnected from " << get_addr().to_string() << ".";
        LOG_INFO.stream() << messages_stat();

		socket->close();
        event_disconnect->happened();
	}
};