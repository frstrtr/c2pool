#pragma once
#include <iostream>
#include <memory>
#include <vector>
#include <cmath>
#include <map>
#include <algorithm>

template <typename VALUE_TYPE, typename SumElementType, typename HASH_TYPE>
class BaseSumElement
{
public:
    typedef SumElementType sum_element_type;
    typedef HASH_TYPE hash_type;
    typedef VALUE_TYPE value_type;

public:
    // For none
    BaseSumElement() {}

    virtual hash_type hash() const = 0;
    virtual hash_type prev() const = 0;

    virtual sum_element_type& add(const sum_element_type &value) = 0;
    virtual sum_element_type& sub(const sum_element_type &value) = 0;

    friend sum_element_type operator+(const sum_element_type & l, const sum_element_type & r)
    {
        sum_element_type result = l;
        result.add(r);
        return result;
    }

    friend sum_element_type operator-(const sum_element_type & l, const sum_element_type & r)
    {
        sum_element_type result = l;
        result.sub(r);
        return result;
    }

    sum_element_type& operator+=(const sum_element_type& value)
    {
        return this->add(value);
    }

    sum_element_type& operator-=(const sum_element_type& value)
    {
        return this->sub(value);
    }
};

template <typename SUM_ELEMENT>
class Node
{
public:
    typedef SUM_ELEMENT sum_element;
    typedef typename SUM_ELEMENT::value_type value_type;
    typedef typename sum_element::hash_type hash_type;
    typedef std::shared_ptr<Node<sum_element>> ptr_node_type;
public:
    // interval indexes:
    int index_l, index_r;

    std::shared_ptr<Node> left, right;
    sum_element sum;

    // for None
    Node() {}

    // from value
    Node(const value_type &_value, int index)
    {
        sum = sum_element(_value);

        index_l = index;
        index_r = index;
    }

    // from sum
    Node(sum_element _sum, int index)
    {
        sum = std::move(_sum);

        index_l = index;
        index_r = index;
    }

//    Node(const ptr_node_type &l, const ptr_node_type &r) : left(l), right(r)
//    {
//        sum = (l ? l->sum : sum_element{}) + (r ? r->sum : sum_element{});
////        sum = l->sum + r->sum;
//
//        index_l = l->index_l;
//        index_r = r->index_r;
//    }

    Node (int i_l, int i_r, ptr_node_type l, ptr_node_type r) : left(l), right(r)
    {
        sum = (l ? l->sum : sum_element{}) + (r ? r->sum : sum_element{});

        index_l = i_l;
        index_r = i_r;
    }

    hash_type hash() const
    {
        if (index_l != index_r)
            throw std::runtime_error("Invalid value for hash in cluster node!");

        return sum.hash();
    }

//    std::shared_ptr<Node> prev;
//    std::shared_ptr<Node> next;
};

template <typename SUM_ELEMENT>
class Cluster
{
public:
    typedef SUM_ELEMENT sum_element;
    typedef typename sum_element::value_type value_type;
    typedef Node<sum_element> node_type;
    typedef std::shared_ptr<node_type> ptr_node_type;
    typedef typename sum_element::hash_type hash_type;
public:
    bool orientation{};
    int begin{}, end{};

    std::map<hash_type, int> reverse; // index by hash element
    std::vector<ptr_node_type> data;
    ptr_node_type head;

private:
    ptr_node_type make_node(const value_type &value, int index)
    {
        return std::make_shared<node_type>(value, index);
    }

    ptr_node_type make_node(const sum_element &sum, int index)
    {
        return std::make_shared<node_type>(sum, index);
    }

    ptr_node_type make_node(int i_l, int i_r, ptr_node_type l, ptr_node_type r)
    {
        return std::make_shared<node_type>(i_l, i_r, l, r);
    }

    ptr_node_type _build_cluster(const std::vector<value_type> &values, int l, int r, const int &start_index = 0)
    {
        if (r < begin || l > end)
        {
            return nullptr;
        }

        ptr_node_type node;

        if (l+1 == r)
        {
            int left_index = l-1 - start_index;
            int right_index = r-1 - start_index;

            data[l] = (left_index < values.size() && left_index >= 0) ? make_node(values[left_index], l) : nullptr;
            if (data[l])
                reverse[data[l]->hash()] = l;

            data[r] = (right_index < values.size() && right_index >= 0 ) ? make_node(values[right_index], r) : nullptr;
            if (data[r])
                reverse[data[r]->hash()] = r;

            node = make_node(l, r, data[l], data[r]);

            return node;
        }

        auto left = _build_cluster(values, l, (l+r)/2, start_index);
        auto right = _build_cluster(values, (l+r)/2+1, r, start_index);
        node = make_node(l, r, left, right);

        return node;
    }

    sum_element _get_sum(ptr_node_type node, int index)
    {
        int l = node->index_l;
        int r = node->index_r;

        if (l > index)
        {
            return {}; // return 0
        }

        if (r <= index)
        {
            return node->sum;
        }
        else // r > index
        {
            return (node->left ? _get_sum(node->left, index) : sum_element{}) + (node->right ? _get_sum(node->right, index) : sum_element{});
        }
    }

    // index for recalculate target
    void recalculate_node(const ptr_node_type &node, const ptr_node_type& value, const int &index)
    {
        if (node)
        {
            if ((node->index_l <= index) && (node->index_r >= index))
            {
                if (node->index_l == node->index_r)
                {
                    node->sum = value->sum;
                    return;
                } else
                {
                    node->sum += value->sum;
                }

                if (!node->left)
                    node->left = make_node(node->index_l, (node->index_l+node->index_r)/2, nullptr, nullptr);
                if (!node->right)
                    node->right = make_node((node->index_l+node->index_r)/2 + 1, node->index_r, nullptr, nullptr);

                recalculate_node(node->left, value, index);
                recalculate_node(node->right, value, index);
            } else
            {
                return;
            }
        }
    }

    sum_element &recalculate_nodes(ptr_node_type &node, const std::map<int, ptr_node_type> &values, const int &l, const int &r)//const int &index)
    {
        // в границах заданного интервала
        if (
                (node->index_l >= l && node->index_r <= r) ||
                (node->index_l <= l && node->index_r >= r) ||
                (node->index_l <= l && node->index_r >= l) ||
                (node->index_l <= r && node->index_r >= r)
                )
        {
            if (node->index_l == node->index_r)
            {
//                node->sum += values.at(node->index_l)->sum;
                node = values.at(node->index_l);
                return node->sum;
            }

            if (!node->left)
                node->left = make_node(node->index_l, (node->index_l + node->index_r) / 2, nullptr, nullptr);
            if (!node->right)
                node->right = make_node((node->index_l + node->index_r) / 2 + 1, node->index_r, nullptr, nullptr);

            node->sum = recalculate_nodes(node->left, values, l, r) + recalculate_nodes(node->right, values, l, r);
            return node->sum;
        } else
        {
            return node->sum;
        }
    }

    // push new element to cluster.begin
    // T = value_type or sum_element
    template <typename T>
    bool push_front(const T& _value)
    {
        if (begin <= 1)
            return false;

        begin -= 1;
        if (end == data.size())
            end -= 1;

        auto value = make_node(_value, begin);

        data[begin] = value;
        reverse[value->hash()] = begin;

        recalculate_node(head, value, begin);


        return true;
    }

    // push new element to cluster.end
    // T = value_type or sum_element
    template <typename T>
    bool push_back(const T& _value)
    {
        if (end >= data.size() - 1)
            return false;

        end += 1;
        if (begin == 0)
            begin += 1;

        auto value = make_node(_value, end);
        data[end] = value;
        reverse[value->hash()] = end;
        recalculate_node(head, value, end);


        return true;
    }

    // push new element to cluster.begin
    // T = value_type or sum_element
    template <typename T>
    bool push_front_range(const std::vector<T> &_values)
    {
        //TODO: добавить возможность разделения заданных данных, чтобы часть добавить сюда, а часть в новый кластер.
        if (begin - _values.size() < 1)
            return false;

        std::map<int, ptr_node_type> values;
        int _i = 0;
        for (int i = begin - _values.size(); i < begin; i++)
        {
            values[i] = make_node(_values[_i], i);
            data[i] = values[i];
            reverse[values[i]->hash()] = i;
            _i += 1;
        }
        recalculate_nodes(head, values, begin - values.size(), begin - 1);

        // update begin
        begin -= _values.size();
        if (end == data.size())
            end -= 1;

        return true;
    }

    // T = value_type or sum_element
    template <typename T>
    bool push_back_range(const std::vector<T> &_values)
    {
        //TODO: добавить возможность разделения заданных данных, чтобы часть добавить сюда, а часть в новый кластер.
        if (end + _values.size() > data.size() - 1)
            return false;

        if (begin == 0)
            begin += 1;

        std::map<int, ptr_node_type> values;
        int i = end + 1;
        for (const auto &v : _values)
        {
            values[i] = make_node(v, i);
            data[i] = values[i];
            reverse[values[i]->hash()] = i;
            i += 1;
        }
        recalculate_nodes(head, values, end + 1, end + _values.size());

        // update end
        end += _values.size();

        return true;
    }

public:
    // empty first element!
    // cluster_orientation -> left (false) -- push_front, right (true) -- push_back
    explicit Cluster(int size, bool cluster_orientation = true) : data({nullptr}), orientation(cluster_orientation)
    {
        int cluster_height = ceil(std::log2(size));
        data.resize(data.size() + std::pow(2, cluster_height));

        if (cluster_orientation)
        {
            begin = 0;
            end = 0;
        } else
        {
            begin = data.size();
            end = data.size();
        }

        head = make_node(1, data.size()-1, nullptr, nullptr);
    }

    explicit Cluster(const std::vector<value_type> &values, bool cluster_orientation = true) : data({nullptr}), orientation(cluster_orientation)
    {
        int cluster_height = ceil(std::log2(values.size()));
        data.resize(data.size() + std::pow(2, cluster_height));

        if (cluster_orientation)
        {
            begin = 1;
            end = begin + values.size() - 1;
            head = _build_cluster(values, 1, data.size() - 1);
        } else
        {
            end = data.size() - 1;
            begin = end - values.size() + 1;
            head = _build_cluster(values, 1, data.size() - 1, data.size()-1 - values.size());
        }

    }

    sum_element get_sum(int index)
    {
         return _get_sum(head, index);
    }

    sum_element get_sum_by_hash(hash_type hash)
    {
        if (exist(hash))
            return get_sum(reverse[hash]);
        else
            return sum_element{}; //TODO: not exis't
    }

    sum_element get_sum_from_head() const
    {
        return head->sum;
    }

    // get sum from interval [l; r]
    sum_element get_sum_range(int l, int r)
    {
        return get_sum(r) - get_sum(l-1);
    }

    sum_element get_sum_range_by_hash(hash_type l, hash_type r)
    {
        if (exist(l) && exist(r))
            return get_sum_range(reverse[l], reverse[r]);
        else
            return sum_element{}; //TODO: not exis't
    }

    sum_element get_element_by_index(int index)
    {
        return data[index]->sum;
    }

    // T = value_type or sum_element
    template <typename T>
    bool insert(T _value)
    {
        // left (false) -- push_front, right (true) -- push_back
        if (orientation)
        {
            return push_back(_value);
        } else
        {
            return push_front(_value);
        }
    }

    // for range
    // T = value_type or sum_element
    template <typename T>
    bool insert(std::vector<T> _values)
    {
        // left (false) -- push_front, right (true) -- push_back
        if (orientation)
        {
            return push_back_range(_values);
        } else
        {
            return push_front_range(_values);
        }
    }

    bool empty() const
    {
        return (begin == 0 && end == 0) || (begin == data.size() && end == data.size());
    }

    bool exist(hash_type hash) const
    {
        return reverse.count(hash) > 0;
    }

    auto get_begin() const
    {
        return begin;
    }

    auto get_end() const
    {
        return end;
    }
};
