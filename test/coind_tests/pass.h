#include <tuple>
#include <string>
using std::string;
using std::tuple, std::make_tuple;

tuple<char*, char*, char*> get_pass(){
    return make_tuple<char*, char*, char*>("user:VeryVeryLongPass123", "192.168.10.10", "14024");
}