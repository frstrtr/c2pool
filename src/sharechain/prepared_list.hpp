#pragma once

#include <map>
#include <vector>
#include <set>
#include <stack>

namespace chain
{
    
template <typename HashType, typename ItemType>
struct PreparedList
{
    using hash_t = HashType;
    using item = ItemType;
    using it_t = typename std::vector<item>::iterator;

    //last->(prev->value)->best
    struct PreparedNode
    {
        item value{};
        PreparedNode *prev_node{};
        std::set<PreparedNode *> next_nodes;

        explicit PreparedNode() { }
        explicit PreparedNode(const item& val) : value(val) { };

        hash_t hash() const
        {
            return value.hash();
        }

        hash_t prev_hash() const
        {
            return value.prev_hash();
        }
    };

    std::map<hash_t, std::set<PreparedNode *>> branch_tails; // value.previous_hash -> value
    std::map<hash_t, PreparedNode *> nodes;

    PreparedList() { }
    PreparedList(std::vector<item>& values) { add(values); }
    ~PreparedList()
    {
        for (auto& [key, node] : nodes)
        {
            if (node)
                delete node;
        }
    }

    PreparedNode *make_node(const item &val)
    {
        auto node = new PreparedNode(val);
        nodes[node->hash()] = node;

        return node;
    }

    static PreparedNode *merge_nodes(PreparedNode *n1, PreparedNode *n2)
    {
        if (n1->hash() == n2->prev_hash())
        {
            n1->next_nodes.insert(n2);
            n2->prev_node = n1;
            return n1;
        } else if (n2->hash() == n1->prev_hash())
        {
            n2->next_nodes.insert(n1);
            n1->prev_node = n2;
            return n1;
        }

        throw std::invalid_argument("can't merge nodes");
    }

    void add(std::vector<item>& values)
    {
        // temp-data
        std::map<hash_t, it_t> items; // hash->item;
        std::map<hash_t, std::vector<it_t>> tails; // хэши, которые являются предыдущими существующим item's.

        for (auto it = values.begin(); it != values.end(); it++)
        {
            items[(*it).hash()] = it;
            tails[(*it).prev_hash()].push_back(it);
        }

        // generate branches
        while (!items.empty())
        {
            // get element from hashes
            auto [hash, value] = *items.begin();
            items.erase(hash);

            PreparedNode *head = make_node(*value);
            PreparedNode *tail = nullptr;
            if (items.count(head->prev_hash()))
            {
                tail = make_node(*items[head->prev_hash()]);
                merge_nodes(tail, head);
                items.erase(head->prev_hash());
            }


            // generate left part of branch
            while (tail && items.count(tail->prev_hash()))
            {
                PreparedNode *new_tail = make_node(*items[tail->prev_hash()]);
                merge_nodes(new_tail, tail);
                items.erase(tail->prev_hash());
                tail = new_tail;
            }

            // generate right part of branch
            while (tails.count(head->hash()))
            {
                PreparedNode *merged_head = nullptr;
                for (auto _head: tails[head->hash()])
                {
                    PreparedNode *new_head = make_node(*_head);
//                    branch_heads[new_head->value.hash].insert(new_head);
                    merged_head = merge_nodes(new_head, head);
                    items.erase(new_head->hash());
                }
                head = merged_head;
            }

            if (tail)
            {
                branch_tails[tail->prev_hash()].insert(tail); // update branch_tails for new tail
            } else
            {
                PreparedNode *new_tail = head;
                while (new_tail->prev_node)
                {
                    new_tail = new_tail->prev_node;
                }

                branch_tails[new_tail->prev_hash()].insert(new_tail);
            }
        }

        //check for merge branch
        // -- heads
        std::set<hash_t> keys_remove;
        for (auto &[k, v]: branch_tails)
        {
            if (nodes.count(k))
            {
                for (auto _tail: v)
                {
                    merge_nodes(nodes[k], _tail);
                }
                keys_remove.insert(k);
            }
        }
        for (auto k : keys_remove){
            branch_tails.erase(k);
        }
    }

    void update_stack(PreparedNode* node, std::stack<PreparedNode*>& st)
    {
        st.push(node);

        if (!node->next_nodes.empty())
        {
            for (const auto &next : node->next_nodes)
                update_stack(next, st);
        }
    }

    auto build_list()
    {
        std::stack<PreparedNode*> st;
        for (const auto &branch : branch_tails)
        {
            for (auto node : branch.second)
            {
//                st.push(node);
                update_stack(node, st);
            }
        }

        std::vector<item> result;
        while (!st.empty())
        {
            result.push_back(st.top()->value);
            st.pop();
        }

        return result;
    };
};

} // namespace chain
