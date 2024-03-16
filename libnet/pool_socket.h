#pragma once

#include <memory>
#include <queue>

#include <libp2p/preset/p2p_socket_data.h>
#include <libp2p/socket.h>
#include <libp2p/message.h>
#include <networks/network.h>
#include <libdevcore/logger.h>

#include <boost/asio.hpp>

typedef BaseSocket<DebugMessages> BasePoolSocket;

class PoolSocket : public BasePoolSocket, public std::enable_shared_from_this<PoolSocket>
{
private:
	std::shared_ptr<boost::asio::ip::tcp::socket> socket;
	c2pool::Network* net;	

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
		LOG_DEBUG_POOL << "PoolSocket created";
	}

	~PoolSocket()
    {
        LOG_DEBUG_POOL << "PoolSocket " << get_addr().to_string() << " removed";
	}

	void write(std::shared_ptr<Message> msg) override
	{
        std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>(msg, net->PREFIX, net->PREFIX_LENGTH);
		LOG_DEBUG_POOL << "\tPool socket write msg: " << msg->command << ", Message data: \n" << *_msg;

        if (_msg->len > 8000000)
        {
            LOG_WARNING << "message length > max_payload_length!";
        }

		event_send_message->happened(msg->command);

		auto socket_ = shared_from_this();
        boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
            [socket_, cmd = msg->command](boost::system::error_code ec, std::size_t length)
            {
				if (ec)
				{
					if (ec != boost::system::errc::operation_canceled)
						socket_->error(libp2p::ASIO_ERROR, (boost::format("[socket] write error (%1%: %2%)") % ec % ec.message()).str());
					else
						LOG_DEBUG_POOL << "PoolSocket::write canceled";
					return;
				}
                
				LOG_DEBUG_POOL << "[PoolSocket] peer receive message_" << cmd;
                socket_->event_peer_receive->happened(cmd);
            }
		);
	}

	// Read
	void read() override
	{
		std::shared_ptr<ReadSocketData> msg = std::make_shared<ReadSocketData>(net->PREFIX_LENGTH);
		read_prefix(msg);
	}

	void init_addr() override
    {
        boost::system::error_code ec;
		auto _addr = socket->remote_endpoint(ec);
		if (ec)
			LOG_WARNING << "PoolSocket init_addr.remote: " << ec << " " << ec.message();
        addr = {socket->remote_endpoint(ec)};

		_addr = socket->local_endpoint(ec);
		if (ec)
			LOG_WARNING << "PoolSocket init_addr.local: " << ec << " " << ec.message();
        addr_local = {socket->local_endpoint(ec)};
    }

	bool is_connected() override
	{
		return socket && socket->is_open();
	}

	void close() override
	{
        LOG_WARNING << "Pool socket has been disconnected from " << get_addr().to_string() << ".";
        LOG_INFO << messages_stat();

		socket->close();
        event_disconnect->happened();
	}
};