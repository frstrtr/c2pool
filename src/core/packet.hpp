#pragma once

namespace c2pool
{

/* Message header:
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class Packet
{
public:
    std::vector<std::byte> prefix;
    std::string command;
    uint32_t message_length;
    uint32_t checksum; // std::byte checksum[4];
    std::vector<std::byte> payload;

    // write
    static PackStream from_message(const std::vector<std::byte>& node_prefix, std::unique_ptr<RawMessage>& msg)
    {
        PackStream result(node_prefix);

        // command
        msg->m_command.resize(12);
        ArrayType<DefaultFormat, 12>::Write(result, msg->m_command);

        // message_length
        result << msg->m_data.size();

        // checksum
        //TODO: check
        uint256 hash_checksum = Hash(std::span<std::byte>(msg->m_data.data(), msg->m_data.size()));
        result << hash_checksum.pn[7];

        // payload
        result << msg->m_data;

        return result;
    }

    // read
    Packet(size_t prefix_length)
    {
        prefix.resize(prefix_length);
    }

    std::unique_ptr<RawMessage> to_message()
    {
        return std::make_unique<RawMessage>(command, PackStream(payload));
    }
};

} // namespace c2pool