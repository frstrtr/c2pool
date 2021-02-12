#pragma once

namespace c2pool::libnet::messages{

    enum commands
    {
        cmd_error = 9999,
        cmd_version = 0,
        cmd_addrs,
        cmd_getaddrs,
        cmd_ping,
        cmd_addrme,
        //new:
        cmd_shares,
        cmd_sharereq,
        cmd_sharereply,
        cmd_best_block, //TODO
        cmd_have_tx,
        cmd_losing_tx
    };

    //for p2pool serialize/deserialize
    class message_p2pool_bytes_converter
    {
    public:
        
        #define COMMAND_LENGTH 12
        #define PAYLOAD_LENGTH 4            //len(payload)
        #define CHECKSUM_LENGTH 4           //sha256(sha256(payload))[:4]
        #define MAX_PAYLOAD_LENGTH 8000000  //max len payload
        int prefix_length;
        const unsigned int unpacked_length();       

    public:
        char *prefix;
        char command[COMMAND_LENGTH + 1];
        char length[PAYLOAD_LENGTH + 1];
        char checksum[CHECKSUM_LENGTH + 1];
        char payload[MAX_PAYLOAD_LENGTH + 1];
        char data[COMMAND_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH + MAX_PAYLOAD_LENGTH]; //full message without prefix //TODO
    private:
        unsigned int _unpacked_length = 0;

    public:
        message_p2pool_bytes_converter() {}

        message_p2pool_bytes_converter(const char *current_prefix);

        void set_data(char *data_);

        void set_unpacked_length(char *packed_len = nullptr);

        //from data to command, length, checksum, payload
        void encode_data();

        //from command, length, checksum, payload to data
        void decode_data();

        int get_length();

    protected:
        //возвращает длину для упакованного payload msg, которое формируется в c2pool.
        virtual int pack_payload_length() { return 0; }

        int set_length(char *data_);
    };

    class message : public message_p2pool_bytes_converter, public std::enable_shared_from_this<message>
    {
    public:
        message(const char *_cmd);

        ~message()
        {
            delete packed_c_str;
        }

        //receive message data from message_p2pool_bytes_converter::command, message_p2pool_bytes_converter::checksum, message_p2pool_bytes_converter::payload, message_p2pool_bytes_converter::unpacked_length;
        //TODO: void receive();
        //receive message data from message_p2pool_bytes_converter::data; use _set_data for init message_p2pool_bytes_converter::data.
        //TODO: void receive_from_data(char *_set_data);
        
        void send();

    protected:
        int pack_payload_length() override;

    private:
        char *packed_c_str;
    };

}