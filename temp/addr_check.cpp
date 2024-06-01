#include <iostream>
#include <core/netaddress.hpp>
#include <core/pack.hpp>
#include <core/packv1.hpp>
#include <core/pack_typesv1.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace legacy
{

struct IPV6AddressType
    {
        std::string value;

        IPV6AddressType()
        {

        }

        IPV6AddressType(std::string _value) : value(_value)
        {

        }

        IPV6AddressType &operator=(std::string _value)
        {
            value = _value;
            return *this;
        }

        std::string get() const
        {
            return value;
        }

        PackStream &write(PackStream &stream)
        {
            std::vector<unsigned char> data;
            if (value.find(':') < value.size())
            {
                boost::erase_all(value, ":");
                data = ParseHex(value);
            } else
            {
                std::vector<std::string> split_res;
                boost::algorithm::split(split_res, value, boost::is_any_of("."));
                if (split_res.size() != 4)
                {
                    throw (std::runtime_error("Invalid address in IPV6AddressType"));
                }

                std::vector<unsigned int> bits;
                for (auto bit: split_res)
                {
                    int bit_int = 0;
                    try
                    {
                        bit_int = boost::lexical_cast<unsigned int>(bit);
                    } catch (boost::bad_lexical_cast const &)
                    {
                        LOG_ERROR << "Error lexical cast in IPV6AddressType";
                    }
                    bits.push_back(bit_int);
                }

                data = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
                for (auto x: bits)
                {
                    data.push_back((unsigned char) x);
                }
            }

            assert(data.size() == 16);

            PackStream _data(data);
            stream << _data;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            std::vector<unsigned char> hex_data{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff};
            if (stream.size() >= 16)
            {
                std::vector<unsigned char> data{stream.data.begin(), stream.data.begin() + 16};
                stream.data.erase(stream.data.begin(), stream.data.begin() + 16);
                bool ipv4 = true;
                for (int i = 0; i < 12; i++)
                {
                    if (data[i] != hex_data[i])
                    {
                        ipv4 = false;
                        break;
                    }
                }

                if (ipv4)
                {
                    std::vector<std::string> nums;
                    for (int i = 12; i < 16; i++)
                    {
                        auto num = std::to_string((unsigned int) data[i]);
                        nums.push_back(num);
                    }
                    value = boost::algorithm::join(nums, ".");
                } else
                {
                    //TODO: IPV6
                }
            } else
            {
                throw std::runtime_error("Invalid address!");
            }
            return stream;
        }
    };

class address_type
{
public:
    /*
        ('services', pack.IntType(64)),
        ('address', pack.IPV6AddressType()),
        ('port', pack.IntType(16, 'big')),
     */
    // unsigned long long services;
    std::string address;
    int port;

    address_type() = default;
    address_type(/*unsigned long long _services,*/ std::string _address, int _port) : address(_address), port(_port) {}

    void print(PackStream& stream) const
    {
        std::cout << address << ":" << port << " -> " << stream << std::endl;
    }

    // friend bool operator==(const address_type &first, const address_type &second);
    // friend bool operator!=(const address_type &first, const address_type &second);

    // NLOHMANN_DEFINE_TYPE_INTRUSIVE(address_type, services, address, port);
};

struct address_type_stream
    {
        // IntType(64) services;
        IPV6AddressType address; //IPV6AddressType
        IntType<uint16_t, true> port;

        PackStream &write(PackStream &stream)
        {
            stream /*<< services*/ << address << port;
            return stream;
        }

        PackStream &read(PackStream &stream)
        {
            stream /*>> services */ >> address >> port;
            return stream;
        }

        address_type_stream &operator=(const address_type &val)
        {
            // services = val.services;
            address = val.address;
            port = val.port;
            return *this;
        }

        address_type get()
        {
            return address_type(/*services.get(),*/ address.get(), port.get());
        }
    };

} // namespace legacy

// void test_v1()
// {
//     std::cout << "TEST V1" << std::endl;
//     legacy::PackStream stream;

//     legacy::IPV6AddressType addr1("192.168.0.1");
//     stream << addr1;
//     std::cout << addr1.value << " -> " << stream << std::endl;

//     legacy::IPV6AddressType addr2;
//     stream >> addr2;
//     std::cout << addr2.value << " -> " << stream << std::endl;
// }

void test_v1()
{
    std::cout << "TEST V1" << std::endl;
    legacy::PackStream stream;

    auto _addr1 = legacy::address_type{"46.19.137.74", 8333};
    legacy::address_type_stream addr1; addr1 = _addr1;
    stream << addr1;
    addr1.get().print(stream);

    legacy::address_type_stream addr2;
    stream >> addr2;
    addr2.get().print(stream);
}

void test_v2()
{
    std::cout << "\nTEST V2" << std::endl;
    PackStream stream;

    NetService service1("46.19.137.74", 8333);
    stream << service1;
    std::cout << service1.address() << ":" << service1.port() << " -> "; stream.print();

    NetService service2;
    stream >> service2;
    std::cout << service2.address() << ":" << service2.port() << " -> "; stream.print();
}

int main()
{
    // v1
    test_v1();

    // v2
    test_v2();
}