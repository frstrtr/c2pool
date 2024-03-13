#pragma once
#include <vector>
#include <memory>

#include "network_tree_node.h"
#include "network_process.h"

#include <boost/asio.hpp>

class NetworkTree
{
    std::unique_ptr<ReconnectProcess> process;
    std::vector<NetworkTreeNode*> chain;
    boost::asio::io_context* ctx;
protected:

    void calculate_chain(NetworkTreeNode* node, std::vector<NetworkTreeNode*>& chain)
    {
        if (node == nullptr)
            return;

        chain.push_back(node);

        for (NetworkTreeNode* next : node->next)
            calculate_chain(next, chain);
    }

    void run()
    {
        for (NetworkTreeNode* node : chain)
        {
            if (node->state == NetworkState::connected)
                continue;

            auto task = process->make_task();

            // push run_node to ctx thread
            boost::asio::post(*ctx, [&](){node->run_node(task);});

            switch (process->wait())
            {
            case cancel:
                return;
            default:
                break;
            }
        }
        std::cout << "RECONNECTED" << std::endl;
    }
    
public:
    NetworkTree() = default;

    void init(boost::asio::io_context* ctx_, NetworkTreeNode* tree_start)
    {
        ctx = ctx_;
        // init tree chain
        calculate_chain(tree_start, chain);
    }

    void restart(NetworkTreeNode* node)
    {
        // new process
        if (process)
        {
            process->cancel();
            // reset unique_ptr process
            process.reset();
        }
        process = std::make_unique<ReconnectProcess>();

        // calculate stop chain
        std::vector<NetworkTreeNode*> stop_chain;
        calculate_chain(node, stop_chain);
        std::reverse(stop_chain.begin(), stop_chain.end());
        
        // stop
        for (auto& v : stop_chain)
            v->stop_node();

        // run
        std::future<void> reconnect_process = std::async(&NetworkTree::run, this);
        process->start(reconnect_process);
    }
};
