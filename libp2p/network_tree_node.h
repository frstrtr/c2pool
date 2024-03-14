#pragma once
#include <vector>
#include "network_process.h"

class NetworkTreeNode
{
    friend class NetworkTree;

    std::shared_ptr<ReconnectTask> task;
    NetworkState state = NetworkState::offline;

    NetworkTreeNode* prev;
    std::vector<NetworkTreeNode*> next;
    
    void run_node(std::shared_ptr<ReconnectTask> task_)
    {
        state = NetworkState::processing;
        task = std::move(task_);
        
        run();
    }

    void stop_node()
    {
        switch (state)
        {
        case NetworkState::offline:
            //TODO: remove
            // stop();
            return;

        case NetworkState::processing:
            task->cancel();
            // continue in "case connected"
        case NetworkState::connected:
            stop();
            break;
        }
        state = NetworkState::offline;
    }

public:
    NetworkTreeNode()
    {

    }

    // call when node connected
    void connected()
    {
        task->ready();
        state = NetworkState::connected;
    }

    void add_next_network_layer(NetworkTreeNode* node)
    {
        next.push_back(node);
        node->prev = this;
    }

    NetworkState get_status() const
    {
        return state;
    }

    bool is_connected() const
    {
        return get_status() == NetworkState::connected;
    }

    virtual void run() = 0;
    virtual void stop() = 0;
};