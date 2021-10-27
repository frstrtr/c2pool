#include <sstream>
using namespace std;

class Converter{
public:
    static int StrToInt(string s){
        stringstream ss;
        ss << s;
        int res;
        ss >> res;
        return res;
    }

};