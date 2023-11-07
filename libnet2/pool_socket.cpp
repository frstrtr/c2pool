#include "pool_socket.h"

#include <libp2p/preset/p2p_socket_data.h>
#include <libdevcore/str.h>

#include <boost/asio.hpp>

// Write
//void PoolSocket::write_prefix(std::shared_ptr<Message> msg)
//{
//	boost::asio::async_write(*socket, boost::asio::buffer(net->PREFIX, net->PREFIX_LENGTH),
//							 [this, msg](boost::system::error_code _ec, std::size_t length)
//							 {
//								 LOG_DEBUG << "PoolSocket: Write prefix called";
//								 if (_ec)
//								 {
//									 LOG_ERROR << "PoolSocket::write()" << _ec << ":" << _ec.message();
//									 return;
//								 }
//								 write_message_data(msg);
//							 });
//}
//
//void PoolSocket::write_message_data(std::shared_ptr<Message> msg)
//{
//	std::shared_ptr<P2PWriteSocketData> _msg = std::make_shared<P2PWriteSocketData>();
//	_msg->from_message(msg);
//
//    std::cout << "write_message_data: ";
//    for (auto v = _msg->data; v != _msg->data+_msg->len; v++)
//    {
//        std::cout << (unsigned int)((unsigned char) *v) << " ";
//    }
//    std::cout << std::endl;
//
//	boost::asio::async_write(*socket, boost::asio::buffer(_msg->data, _msg->len),
//							 [&, cmd = msg->command](boost::system::error_code _ec, std::size_t length)
//							 {
//								 LOG_DEBUG << "PoolSocket: Write msg data called: " << cmd;
//								 if (_ec)
//								 {
//									 LOG_ERROR << "PoolSocket::write()" << _ec << ":" << _ec.message();
//								 }
//							 });
//}

// Read
void PoolSocket::read_prefix(std::shared_ptr<ReadSocketData> msg)
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
                                        std::string reason = "[PoolSocket] prefix doesn't match: ";
                                        bad_peer->happened(reason);
                                    }
								}
								else
								{
                                    std::string reason = "[PoolSocket] read_prefix: " + ec.message();
                                    bad_peer->happened(reason);
								}
							});
}

void PoolSocket::read_command(std::shared_ptr<ReadSocketData> msg)
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
                                    std::string reason = "[PoolSocket] read_command: " + ec.message();
                                    bad_peer->happened(reason);
								}
							});
}

void PoolSocket::read_length(std::shared_ptr<ReadSocketData> msg)
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
                                    std::string reason = "[PoolSocket] read_length: " + ec.message();
                                    bad_peer->happened(reason);
								}
							});
}

void PoolSocket::read_checksum(std::shared_ptr<ReadSocketData> msg)
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
                                    std::string reason = "[PoolSocket] read_checksum: " + ec.message();
                                    bad_peer->happened(reason);
								}
							});
}

void PoolSocket::read_payload(std::shared_ptr<ReadSocketData> msg)
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
									// LOG_INFO << "read_payload";
//									LOG_DEBUG << "HANDLE MESSAGE!";
									final_read_message(msg);
									read();
								}
								else
								{
                                    std::string reason = "[PoolSocket] read_payload: " + ec.message();
                                    bad_peer->happened(reason);
								}
							});
}

void PoolSocket::final_read_message(std::shared_ptr<ReadSocketData> msg)
{
	//checksum check
	auto checksum = coind::data::hash256(PackStream(msg->payload, msg->unpacked_len), true).GetChars();
    if (!c2pool::dev::compare_str(checksum.data(), msg->checksum, 4))
    {
        auto [ip, port] = get_addr();
        std::string reason = "[PoolSocket] final_read_message: Invalid hash for " + ip + ":" + port + ", command = " + msg->command;
        bad_peer->happened(reason);
        return;
    }

	//Make raw message
	PackStream stream_RawMsg;

	std::string cmd(msg->command);
	PackStream stream_payload(msg->payload, msg->unpacked_len);

	stream_RawMsg << stream_payload;

	shared_ptr<RawMessage> raw_message = std::make_shared<RawMessage>(cmd);
	stream_RawMsg >> *raw_message;

    // Set last_message_received
    last_message_received = msg->command;

	//Protocol handle message
	handler(raw_message);
}
