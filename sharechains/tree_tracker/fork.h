#pragma once
#include <deque>
#include "cluster.h"

//class fake_share
//{
//public:
//    int hash;
//    int previous_hash;
//
//    int work;
//
//    fake_share(int _hash, int _prev, int _work)
//    {
//        hash = _hash;
//        previous_hash = _prev;
//        work = _work;
//    }
//};
//
//class FakeShareSum : public BaseSumElement<std::shared_ptr<fake_share>, FakeShareSum, uint64_t>
//{
//public:
//    std::shared_ptr<fake_share> share;
//
//    uint64_t height;
//    int work;
//
//    FakeShareSum()
//    {
//        height = 0;
//        work = 0;
//    }
//
//    FakeShareSum(const std::shared_ptr<fake_share>& _share) : share(_share)
//    {
//        height = 1;
//        work = _share->work;
//    }
//
//    sum_element_type& add(const sum_element_type &value) override
//    {
//        height += value.height;
//        work += value.work;
//        return *this;
//    }
//
//    sum_element_type& sub(const sum_element_type &value) override
//    {
//        height -= value.height;
//        work -= value.work;
//        return *this;
//    }
//
//    hash_type hash() const override
//    {
//        return share->hash;
//    }
//
//    hash_type prev() const override
//    {
//        return share->previous_hash;
//    }
//};

//template <typename CLUSTER_SUM_ELEMENT>
template <typename SumType, int SIZE = 8192>
class Fork
{
public:
    typedef Cluster<SumType> cluster_type;
    typedef typename cluster_type::value_type value_type;
    typedef typename cluster_type::sum_element sum_element;
    typedef int hash_type;
    const int cluster_size = SIZE;
//  TODO:  const int cluster_size = 8192;
public:
    std::deque<cluster_type> clusters;
    hash_type head{}, tail{};
    std::shared_ptr<Fork<SumType, SIZE>> prev_fork = nullptr;

    Fork()
    {
        clusters.emplace_front(cluster_size, false); // front cluster
        clusters.emplace_back(cluster_size, true);   // back  cluster
    }

    void insert(sum_element value)
    {
        // TODO: optimize call empty(), cache in var!
        if (empty())
        {
            clusters.back().insert(value);

            head = value.hash();
            tail = value.prev();

            return;
        }

        if (value.hash() == tail)
        {
            // insert to front
            while (!clusters.front().insert(value))
                clusters.emplace_back(cluster_size, false); // emplace left orientation

            tail = value.prev();
            return;
        }

        if (value.prev() == head)
        {
            // insert to back
            while (!clusters.back().insert(value))
                clusters.emplace_back(cluster_size, true); // emplace right orientation

            head = value.hash();
            return;
        }
    }

    void insert_fork(std::shared_ptr<Fork<SumType, SIZE>> _fork)
    {
        prev_fork = _fork;
    }

    bool empty() const
    {
        return !std::any_of(clusters.begin(), clusters.end(), [](const auto& cl){return !cl.empty();});
    }

    sum_element get_sum(hash_type hash)
    {
        sum_element result;
        for (auto &cluster : clusters)
        {
            if (cluster.exist(hash))
            {
                result += cluster.get_sum_by_hash(hash);
                break;
            } else
            {
                result += cluster.get_sum_from_head();
            }
        }

        return result;
    }

    // result -> (left_hash, right_hash]
    sum_element get_sum_range(hash_type left_hash, hash_type right_hash)
    {
        return get_sum(right_hash) - get_sum(left_hash);
    }

    sum_element get_sum_all()
    {
        return get_sum(head);
    }
};
