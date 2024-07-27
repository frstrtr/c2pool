#include <iostream>
#include <unordered_map>
#include <ranges>


struct ChainData
{
    std::string m_data;
    int m_prev;

    ChainData() {}
    ChainData(std::string data, int prev) : m_data(data), m_prev(prev) { }
};

class Chain
{
    using data_t = std::unordered_map<int, ChainData>;
private:
    data_t m_data;

public:

    struct Iterator
    {
        typename data_t::iterator m_it;
        Chain& m_chain;

        std::pair<const int, ChainData>& operator*() {
            return *m_it;
        }

        Iterator& operator++() {
            m_it = m_chain.m_data.find(m_it->second.m_prev);
            return *this;
        }

        bool operator!=(const Iterator& other) const {
            // std::cout << "flag: " << (m_it != other.m_it) << std::endl;
            return m_it != other.m_it;
        }

        Iterator(Chain& chain, typename data_t::iterator it) : m_chain(chain), m_it(it) { }
    };

    struct ChainView
    {
        Chain& m_chain;
        int m_start;
        size_t m_count;

        ChainView(Chain& chain, int start, size_t n) : m_chain(chain), m_start(start), m_count(n) { }

        Iterator begin()
        {
            std::cout << "call begin" << std::endl;
            return Iterator(m_chain, m_chain.m_data.find(m_start));
        }

        Iterator end()
        {
            std::cout << "call end" << std::endl;
            typename data_t::iterator it = m_chain.m_data.find(m_start);
            for (int i = 0; i <= m_count; i++)
            {
                if (m_chain.m_data.contains(it->second.m_prev))
                    it = m_chain.m_data.find(it->second.m_prev);
                else
                    it = m_chain.m_data.end();
            }
            return Iterator(m_chain, it);
        }
    };

    void add(int hash, ChainData data) { m_data[hash] = data; }

    ChainView get_chain(int start, size_t n)
    {
        return ChainView(*this, start, n);
    }
};


int main()
{
    Chain chain;

    chain.add(1, {"!", 0});
    chain.add(2, {"world", 1});
    chain.add(3, {",", 2});
    chain.add(4, {"hello", 3});

    for (auto& element : chain.get_chain(4, 3))
    {
        // std::cout << element.first << std::endl;
        std::cout << element.second.m_data;
    }
    std::cout << std::endl;
}