// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
#include <string>

namespace jsonrpccxx {
    class IClientConnector {
    public:
        virtual ~IClientConnector() = default;
        virtual std::string Send(const std::string &request) = 0;
    };
}