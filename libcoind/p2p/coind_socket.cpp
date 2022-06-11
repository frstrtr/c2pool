#include "p2p_socket.h"

#include "p2p_socket_data.h"

#include <boost/asio.hpp>

// Write
void P2PSocket::write_prefix(std::shared_ptr<Message> msg)
{
	boost::asio::async_write(socket, boost::asio::buffer(net->PREFIX, net->PREFIX_LENGTH),
							 [this, msg](boost::system::error_code _ec, std::size_t length)
							 {
								 LOG_DEBUG << "Write prefix called";
								 if (_ec)
								 {
									 LOG_ERROR << "P2PSocket::write()" << _ec << ":" << _ec.message();
									 return;
								 }
								 write_message_data(msg);
							 });
}

void P2PSocket::write_message_data(std::shared_ptr<Message> msg)
{
	std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>();
	_msg->from_message(msg);

	boost::asio::async_write(socket, boost::asio::buffer(_msg->data, _msg->len),
							 [&](boost::system::error_code _ec, std::size_t length)
							 {
								 LOG_DEBUG << "Write msg data called";
								 if (_ec)
								 {
									 LOG_ERROR << "P2PSocket::write()" << _ec << ":" << _ec.message();
								 }
							 });
}

// Read
void P2PSocket::read_prefix(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(socket,
							boost::asio::buffer(msg->prefix, net->PREFIX_LENGTH),
							[this, msg](boost::system::error_code ec, std::size_t length)
							{
								LOG_TRACE << "try to read prefix";
								//TODO: compare
								if (!ec /*&& c2pool::dev::compare_str(tempRawMessage->converter->prefix, _net->PREFIX, tempRawMessage->converter->get_prefix_len())*/)
								{
									LOG_TRACE << "compare prefix";
									//c2pool::python::other::debug_log(tempRawMessage->converter->prefix, _net->PREFIX_LENGTH);
									LOG_TRACE << "after debug_log";
									// LOG_INFO << "MSG: " << tempMessage->command;
									read_command(msg);
								}
								else
								{
									LOG_ERROR << "read_prefix: " << ec << " " << ec.message();
									disconnect();
								}
							});
}

void P2PSocket::read_command(std::shared_ptr<ReadSocketData> msg)
{

	boost::asio::async_read(socket,
							boost::asio::buffer(msg->command, msg->COMMAND_LEN),
							[this, msg](boost::system::error_code ec, std::size_t /*length*/)
							{
								if (!ec)
								{
									LOG_TRACE << "try to read command: " << msg->command;
									//LOG_INFO << "read_command";
									read_length(msg);
								}
								else
								{
									LOG_ERROR << ec << " " << ec.message();
									disconnect();
								}
							});
}

void P2PSocket::read_length(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(socket,
							boost::asio::buffer(msg->len, msg->LEN_LEN),
							[this, msg](boost::system::error_code ec, std::size_t /*length*/)
							{
								if (!ec)
								{
									LOG_TRACE << "try to read length";
									// LOG_INFO << "read_length";
									read_checksum(msg);
								}
								else
								{
									LOG_ERROR << ec << " " << ec.message();
									disconnect();
								}
							});
}

void P2PSocket::read_checksum(std::shared_ptr<ReadSocketData> msg)
{
	boost::asio::async_read(socket,
							boost::asio::buffer(msg->checksum, msg->CHECKSUM_LEN),
							[this, msg](boost::system::error_code ec, std::size_t /*length*/)
							{
								if (!ec)
								{
									LOG_TRACE << "try to read checksum";
									// LOG_INFO << "read_checksum";
									read_payload(msg);
								}
								else
								{
									LOG_ERROR << ec << " " << ec.message();
									disconnect();
								}
							});
}

void P2PSocket::read_payload(std::shared_ptr<ReadSocketData> msg)
{
	PackStream stream_len(msg->len, msg->LEN_LEN);
	IntType(32) payload_len;
	stream_len >> payload_len;
	msg->unpacked_len = payload_len.get();
	msg->payload = new char[msg->unpacked_len+1];

	boost::asio::async_read(socket,
							boost::asio::buffer(msg->payload, msg->unpacked_len),
							[this, msg](boost::system::error_code ec, std::size_t length)
							{
								if (!ec)
								{
									// LOG_INFO << "read_payload";
									LOG_DEBUG << "HANDLE MESSAGE!";
									final_read_message(msg);
									read();
								}
								else
								{
									LOG_ERROR << "read_payload: " << ec << " " << ec.message();
									disconnect();
								}
							});
}

void P2PSocket::final_read_message(std::shared_ptr<ReadSocketData> msg)
{
	//checksum check
	//TODO: !!!

	//Make raw message
	PackStream stream_RawMsg;

//        PackStream stream_command(msg->command, msg->COMMAND_LEN);
	std::string cmd(msg->command);
	PackStream stream_payload(msg->payload, msg->unpacked_len);

	stream_RawMsg << stream_payload;

	shared_ptr<RawMessage> raw_message = std::make_shared<RawMessage>(cmd);
	//RawMessage->name_type = reverse_string_commands(msg->command);
	stream_RawMsg >> *raw_message;

	//Protocol handle message
	handler(raw_message);
}
