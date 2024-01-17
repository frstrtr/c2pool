#pragma once
#include <deque>
#include <memory>
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

template <typename SumType, int SIZE>
class SubFork;

//template <typename CLUSTER_SUM_ELEMENT>
template <typename SumType, int SIZE = 8192>
class Fork : public std::enable_shared_from_this<Fork<SumType, SIZE>>
{
public:
    typedef Cluster<SumType> cluster_type;
    typedef typename cluster_type::value_type value_type;
    typedef typename cluster_type::sum_element sum_element;
    typedef uint256 hash_type;
    const int cluster_size = SIZE;
public:
    std::deque<cluster_type> clusters;
    hash_type head{}, tail{};
    std::shared_ptr<Fork<SumType, SIZE>> prev_fork = nullptr;
    std::vector<std::shared_ptr<Fork<SumType, SIZE>>> sub_forks;

    Fork()
    {
        clusters.emplace_front(cluster_size, false); // front cluster
        clusters.emplace_back(cluster_size, true);   // back  cluster
    }

    virtual hash_type get_head() const
    {
        return head;
    }

    virtual hash_type get_tail() const
    {
        return tail;
    }

    virtual std::shared_ptr<Fork<SumType, SIZE>> get_prev_fork() const
    {
        return prev_fork;
    }

    virtual void insert(sum_element value)
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
                clusters.emplace_front(cluster_size, false); // emplace left orientation

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

    virtual void insert_fork(std::shared_ptr<Fork<SumType, SIZE>> _fork)
    {
        prev_fork = _fork;
    }

    virtual void insert_fork(std::shared_ptr<Fork<SumType, SIZE>> _fork, hash_type pos)
    {
        auto sub_fork = std::make_shared<SubFork<SumType, SIZE>>(_fork, pos);
        _fork->sub_forks.push_back(sub_fork);

        prev_fork = sub_fork;
    }

    virtual bool empty() const
    {
        return !std::any_of(clusters.begin(), clusters.end(), [](const auto& cl){return !cl.empty();});
    }

    virtual sum_element get_sum(hash_type hash)
    {
        sum_element result;
        for (auto &cluster : clusters)
        {
            if (cluster.exist(hash))
            {
                result += cluster.get_sum_by_hash(hash);
                break;
            }

            result += cluster.get_sum_from_head();
        }

        return result;
    }

    virtual sum_element get_sum_element(hash_type hash)
    {
        for (auto &cluster : clusters)
        {
            if (cluster.exist(hash))
            {
                return cluster.data[cluster.reverse[hash]]->sum;
            }
        }

        throw std::out_of_range("fork.get_sum_element: hash not found");
    }

    // result -> (left_hash, right_hash]
    sum_element get_sum_range(hash_type left_hash, hash_type right_hash)
    {
        return get_sum(right_hash) - get_sum(left_hash);
    }

    virtual sum_element get_sum_all()
    {
        return get_sum(get_head());
    }

    virtual hash_type get_chain_tail() const
    {
        auto _fork = this->shared_from_this();
        while (_fork->get_prev_fork())
        {
            _fork = _fork->get_prev_fork();
        }
        return _fork->get_tail();
    }
};

template <typename SumType, int SIZE = 8192>
class SubFork : public Fork<SumType, SIZE>
{
private:
    typedef Fork<SumType, SIZE> fork_type;
    typedef typename fork_type::hash_type hash_type;
    typedef typename fork_type::sum_element sum_element;
public:
    std::shared_ptr<fork_type> fork;
    hash_type split_point; // точка разделения на sub_fork.

    SubFork(const std::shared_ptr<fork_type> &_fork, const hash_type &_point) : Fork<SumType, SIZE>(), fork(_fork), split_point(_point)
    {
        this->prev_fork = fork->prev_fork;
    }

    virtual hash_type get_head() const override
    {
        return fork->head;
    }

    virtual hash_type get_tail() const override
    {
        return fork->tail;
    }

    virtual std::shared_ptr<Fork<SumType, SIZE>> get_prev_fork() const override
    {
        return fork->prev_fork;
    }

    void insert(sum_element value) override
    {
        throw std::logic_error("Try to insert value in SubFork!");
    }

    virtual bool empty() const override
    {
        return fork->empty();
    }

    sum_element get_sum(hash_type hash) override
    {
        sum_element result;

        //cluster_num, pos;
        std::optional<int> split_pos;

        for (auto &cluster : fork->clusters)
        {
            if (!split_pos & cluster.exist(split_point))
                split_pos = cluster.reverse[split_point];

            if (cluster.exist(hash))
            {
                if (!split_pos || split_pos < cluster.reverse[hash])
                    throw std::invalid_argument("split_point should be to the right of hash");
                result += cluster.get_sum_by_hash(hash);
                break;
            }

            result += cluster.get_sum_from_head();
        }

        return result;
    }

    sum_element get_sum_element(hash_type hash) override
    {
        //cluster_num, pos;
        std::optional<int> split_pos;

        for (auto &cluster : fork->clusters)
        {
            if (!split_pos & cluster.exist(split_point))
                split_pos = cluster.reverse[split_point];

            if (cluster.exist(hash))
            {
                if (!split_pos || split_pos < cluster.reverse[hash])
                    throw std::invalid_argument("split_point should be to the right of hash");

                return cluster.data[cluster.reverse[hash]]->sum;
            }
        }
        throw std::out_of_range("fork.get_sum_element: hash not found");
    }

    void insert_fork(std::shared_ptr<Fork<SumType, SIZE>> _fork, typename fork_type::hash_type pos) override
    {
        throw std::logic_error("Try to insert fork in SubFork!");
    }

    sum_element get_sum_all() override
    {
        return get_sum(split_point);
    }
};