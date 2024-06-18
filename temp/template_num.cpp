#include <iostream>
#include <map>

template <int I>
struct Base
{
    static std::map<int, int> OpMap;

private:
      static std::map<int, int> init_map() {
          std::map<int, int> some_map;
          some_map[100 + I] = 50 + I;
          some_map[50 + I] = 25 + I;
          return some_map;
      }
};

template <int I>
std::map<int, int> Base<I>::OpMap = Base<I>::init_map();
// {
//     {100, 50},
//     {50, 25}
// };

template <int... Is>
class Bases
{
public:
    static std::map<int, int> OpMap;

private:
    static std::map<int, int> init_map() {
        std::map<int, int> some_map;
        ((some_map[Is] = 100 + Is), ...);
        return some_map;
    } 
};

template <int... Is>
std::map<int, int> Bases<Is...>::OpMap = Bases<Is...>::init_map();

int main()
{
    // std::cout << Base<15>::OpMap[15] << std::endl;
    int i;
    std::cin >> i;
    std::cout << Bases<1, 2, 3, 4>::OpMap[i] << std::endl;
}