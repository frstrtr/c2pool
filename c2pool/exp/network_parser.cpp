#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/filesystem/operations.hpp>
#include <networks/network.h>

void make_default_network()
{

};

int main()
{
    std::vector net_names {"digibyte"};
//    std::cout << "path: " << boost::filesystem::current_path() << std::endl;
//    std::exit(0);

    for (auto name : net_names)
    {
        auto path = boost::filesystem::current_path() / name;

        boost::system::error_code ec;
        boost::filesystem::create_directories(path, ec);
        if (!ec)
        {
            std::fstream f((path/"test_config.cfg").string(), ios_base::out);

            using boost::property_tree::ptree;

            ptree root;

            ptree network;
            network.put( "width", "1" );
            network.put( "position", "2.0" );

            std::vector<std::string> array{"1","sd", "bb"};
            std::string s_array;
            for (auto v : array)
            {
                s_array += v + " ";
            }
            network.add("array", s_array);
//            network.add_child("array", array_ar);


            root.push_front(
                    ptree::value_type( "network", network)
            );

            write_ini(f, root);
        } else
        {
            std::cout << "Error when opening network .cfg: " << ec.message() << std::endl;
        }

        std::cout << path << std::endl;
    }
    std::exit(0);


    std::fstream f("test_config.cfg", ios_base::out);

    using boost::property_tree::ptree;

    ptree root;

    ptree wave_packet;
    wave_packet.put( "width", "1" );
    wave_packet.put( "position", "2.0" );

    ptree calculation_parameters;
    calculation_parameters.put( "levels", "15" );

    root.push_front(
            ptree::value_type( "calculation parameters", calculation_parameters )
    );
    root.push_front(
            ptree::value_type( "wave packet", wave_packet )
    );

    write_ini(f, root);
    return 0;
}