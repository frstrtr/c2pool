#include <iostream>

#include <core/log.hpp>
#include <core/settings.hpp>
#include <core/fileconfig.hpp>

#include <core/uint256.hpp>

#include <pool/node.hpp>

class ILegacy
{
    virtual void handle_version() = 0;
};

class IActual
{
    virtual void handle_version() = 0;
};

class TestNode : c2pool::pool::Node<ILegacy, IActual>
{
    int num;
    // void Legacy::handle_version() override
    // {

    // }

    // void Actual::handle_version() override
    // {

    // }
};



int main(int argc, char *argv[])
{
    c2pool::log::Logger::init();
    auto settings = c2pool::Fileconfig::load_file<c2pool::Settings>();



    TestNode* node = new TestNode();
}