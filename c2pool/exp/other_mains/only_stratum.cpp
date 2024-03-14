#include <iostream>
#include <memory>

#include <libcoind/jsonrpc/stratum.h>

int main(int ac, char *av[])
{
    std::shared_ptr<Stratum> stratum = std::make_shared<Stratum>()
}