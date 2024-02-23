#pragma once

#include <cstdint>
#include <memory>

#include "message.h"
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
struct ReadSocketData
{
    const int COMMAND_LEN = 12;
    const int LEN_LEN = 4;
    const int CHECKSUM_LEN = 4;

    char *prefix;
    char *command;
    char *len;
    char *checksum;
    char *payload;

    int32_t unpacked_len;

    ReadSocketData(int32_t pref_len) : payload(nullptr)
    {
        prefix = new char[pref_len];
        command = new char[COMMAND_LEN];
        len = new char[LEN_LEN];
        checksum = new char[CHECKSUM_LEN];
    }

    ~ReadSocketData()
    {
        delete[] prefix;
        delete[] command;
        delete[] len;
        delete[] checksum;
        if (payload)
        {
            delete[] payload;
        }
    }
};

struct WriteSocketData
{
    char *data;
    int32_t len;

    WriteSocketData() {}
    WriteSocketData(char *_data, int32_t _len) : data(_data), len(_len) { }

    ~WriteSocketData()
    {
        if (data != nullptr)
        {
            delete []data;
        }
    }

    virtual void from_message(std::shared_ptr<Message> msg) = 0;
};