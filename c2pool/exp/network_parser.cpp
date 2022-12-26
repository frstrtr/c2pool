#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <networks/network.h>

int main()
{
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