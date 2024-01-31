#include "coind_socket.h"

#include <libp2p/preset/p2p_socket_data.h>
#include <libdevcore/str.h>
#include <libdevcore/exceptions.h>

#include <boost/asio.hpp>

// Read
void CoindSocket::read_prefix(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(*socket,
							boost::asio::buffer(msg->prefix, net->PREFIX_LENGTH),
							[this, msg](boost::system::error_code ec, std::size_t length)
							{
								if (!ec)
								{
                                    if (c2pool::dev::compare_str(msg->prefix, net->PREFIX, length))
                                    {
                                        read_command(msg);
                                    } else {
										throw make_except<coind_exception, NodeExcept>("[socket] prefix doesn't match");
                                    }
								}
								else
								{
									throw make_except<coind_exception, NodeExcept>((boost::format("[socket] read_prefix (%1%: %2%)") % ec % ec.message()).str());
								}
							});
}

void CoindSocket::read_command(std::shared_ptr<ReadSocketData> msg)
{

	boost::asio::async_read(*socket,
							boost::asio::buffer(msg->command, msg->COMMAND_LEN),
							[this, msg](boost::system::error_code ec, std::size_t /*length*/)
							{
								if (!ec)
								{
									read_length(msg);
								}
								else
								{
									throw make_except<coind_exception, NodeExcept>((boost::format("[socket] read_command (%1%: %2%)") % ec % ec.message()).str());
								}
							});
}

void CoindSocket::read_length(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(*socket,
							boost::asio::buffer(msg->len, msg->LEN_LEN),
							[this, msg](boost::system::error_code ec, std::size_t /*length*/)
							{
								if (!ec)
								{
									read_checksum(msg);
								}
								else
								{
                                    throw make_except<coind_exception, NodeExcept>((boost::format("[socket] read_length (%1%: %2%)") % ec % ec.message()).str());
								}
							});
}

void CoindSocket::read_checksum(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(*socket,
							boost::asio::buffer(msg->checksum, msg->CHECKSUM_LEN),
							[this, msg](boost::system::error_code ec, std::size_t /*length*/)
							{
								if (!ec)
								{
									read_payload(msg);
								}
								else
								{
                                    throw make_except<coind_exception, NodeExcept>((boost::format("[socket] read_checksum (%1%: %2%)") % ec % ec.message()).str());
								}
							});
}

void CoindSocket::read_payload(std::shared_ptr<ReadSocketData> msg)
{
	PackStream stream_len(msg->len, msg->LEN_LEN);
	IntType(32) payload_len;
	stream_len >> payload_len;
	msg->unpacked_len = payload_len.get();
	msg->payload = new char[msg->unpacked_len+1];

	boost::asio::async_read(*socket,
							boost::asio::buffer(msg->payload, msg->unpacked_len),
							[this, msg](boost::system::error_code ec, std::size_t length)
							{
								if (!ec)
								{
									final_read_message(msg);
									read();
								}
								else
								{
                                    throw make_except<coind_exception, NodeExcept>((boost::format("[socket] read_payload (%1%: %2%)") % ec % ec.message()).str());
								}
							});
}

void CoindSocket::final_read_message(std::shared_ptr<ReadSocketData> msg)
{
	//checksum check
    auto checksum = coind::data::hash256(PackStream(msg->payload, msg->unpacked_len), true).GetChars();
    if (!c2pool::dev::compare_str(checksum.data(), msg->checksum, 4))
    {
        auto [ip, port] = get_addr();
		throw make_except<coind_exception, NodeExcept>((boost::format("[socket] Invalid hash for %1%:%2%, command %3%") % ip % port % msg->command).str());
    }

	//Make raw message
	PackStream stream_RawMsg;

//        PackStream stream_command(msg->command, msg->COMMAND_LEN);
	std::string cmd(msg->command);
	PackStream stream_payload(msg->payload, msg->unpacked_len);

	stream_RawMsg << stream_payload;

	shared_ptr<RawMessage> raw_message = std::make_shared<RawMessage>(cmd);
	//RawMessage->name_type = reverse_string_commands(msg->command);
	stream_RawMsg >> *raw_message;

    // Set last_message_received
    last_message_received = msg->command;

	//Protocol handle message
	handler(raw_message);
}
