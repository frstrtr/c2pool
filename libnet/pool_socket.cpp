#include "pool_socket.h"

#include <libp2p/preset/p2p_socket_data.h>
#include <libdevcore/str.h>

#include <boost/asio.hpp>

// Read
void PoolSocket::read_prefix(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(*socket, boost::asio::buffer(msg->prefix, net->PREFIX_LENGTH),
		[this, msg](boost::system::error_code ec, std::size_t length)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_prefix (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_POOL << "PoolSocket::read_prefix canceled";
				return;
			}

			if (c2pool::dev::compare_str(msg->prefix, net->PREFIX, length))
                read_command(msg);
            else
				error(libp2p::BAD_PEER, "[socket] prefix doesn't match");
		}
	);
}

void PoolSocket::read_command(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(*socket, boost::asio::buffer(msg->command, msg->COMMAND_LEN),
		[this, msg](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_command (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_POOL << "PoolSocket::read_command canceled";
				return;
			}

			read_length(msg);
		}
	);
}

void PoolSocket::read_length(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(*socket, boost::asio::buffer(msg->len, msg->LEN_LEN),
		[this, msg](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_length (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_POOL << "PoolSocket::read_length canceled";
				return;
			}

			read_checksum(msg);
		}
	);
}

void PoolSocket::read_checksum(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(*socket, boost::asio::buffer(msg->checksum, msg->CHECKSUM_LEN),
		[this, msg](boost::system::error_code ec, std::size_t /*length*/)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_checksum (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_POOL << "PoolSocket::read_checksum canceled";
				return;
			}

			read_payload(msg);
		}
	);
}

void PoolSocket::read_payload(std::shared_ptr<ReadSocketData> msg)
{
	PackStream stream_len(msg->len, msg->LEN_LEN);
	IntType(32) payload_len;
	stream_len >> payload_len;
	msg->unpacked_len = payload_len.get();
	msg->payload = new char[msg->unpacked_len+1];

	boost::asio::async_read(*socket, boost::asio::buffer(msg->payload, msg->unpacked_len),
		[this, msg](boost::system::error_code ec, std::size_t length)
		{
			if (ec)
			{
				if (ec != boost::system::errc::operation_canceled)
					error(libp2p::ASIO_ERROR, (boost::format("[socket] read_payload (%1%: %2%)") % ec % ec.message()).str());
				else
					LOG_DEBUG_POOL << "PoolSocket::read_payload canceled";
				return;
			}

			final_read_message(msg);
			read();
		}
	);
}

void PoolSocket::final_read_message(std::shared_ptr<ReadSocketData> msg)
{
	//checksum check
	auto checksum = coind::data::hash256(PackStream(msg->payload, msg->unpacked_len), true).GetChars();
    if (!c2pool::dev::compare_str(checksum.data(), msg->checksum, 4))
    {
		error(libp2p::BAD_PEER, (boost::format("[socket] Invalid hash for %1%, command %2%") % get_addr().to_string() % msg->command).str());
		return;
    }

	//Make raw message
	PackStream stream_RawMsg;

	std::string cmd(msg->command);
	PackStream stream_payload(msg->payload, msg->unpacked_len);

	stream_RawMsg << stream_payload;

	shared_ptr<RawMessage> raw_message = std::make_shared<RawMessage>(cmd);
	stream_RawMsg >> *raw_message;

    event_handle_message->happened(msg->command);
	//Protocol handle message
	msg_handler(raw_message);
}
