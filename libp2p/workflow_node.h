#pragma once
#include <vector>
#include <mutex>
#include <memory>

#include "workflow_task.h"
#include "workflow_process.h"


enum WorkflowState
{
    disconnected = 0,
    processing_connect = 1,
    processing_disconnect = 1 << 1,
    connected = 1 << 2
};

class WorkflowNode
{
    friend class WorkflowTree;

protected:
    WorkflowNodeProcess process;
    mutable std::mutex mutex;

    std::shared_ptr<WorkflowTask> run_task;
    std::shared_ptr<WorkflowTask> stop_task;
    WorkflowState state {WorkflowState::disconnected};
    
    WorkflowNode* prev;
    std::vector<WorkflowNode*> next;

protected:
    // called from Workflow thread!
    virtual void run_node() = 0;
    // called from Workflow thread!
    virtual void stop_node() = 0;

    // non-thread safe
    // call when node connected
    void connected()
    {
        std::lock_guard lk(mutex);
        state = WorkflowState::connected;
        
        run_task->ready();
        run_task.reset();
    }

    // non-thread safe
    // call when node disconnected, preferably from a destructor WorkflowNodeProcess::process
    void disconnected()
    {
        std::lock_guard lk(mutex);
        state = WorkflowState::disconnected;

        if (stop_task)
            stop_task->ready();
        stop_task.reset();
    }
private:
    void update_task(const std::shared_ptr<WorkflowTask>& new_task)
    {
        switch (new_task->type)
        {
        case TaskType::STOP_TASK:
            stop_task = new_task;
            break;
        
        case TaskType::RUN_TASK:
            run_task = new_task;
            break;

        default:
            std::cout << "ERROR upd task" << std::endl;
            break;
        }
    }

    // call from boost::io_context
    void run(const std::shared_ptr<WorkflowTask>& task_)
    {
        std::lock_guard lk(mutex);

        state = WorkflowState::processing_connect;

        process = WorkflowNodeProcess::make(
            // called when process finished [deleted]
            [&]
            {
                disconnected();
            },
            mutex
        );
        run_node();
    }

    // call from boost::io_context
    void stop(const std::shared_ptr<WorkflowTask>& task_)
    {
        state = WorkflowState::processing_disconnect;

        // update_task(task_);
        process.stop();
        stop_node();
        process.reset();
    }

public:
    WorkflowNode()
    {

    }

    void add_next_network_layer(WorkflowNode* node)
    {
        std::lock_guard lk(mutex);
        next.push_back(node);
        node->prev = this;
    }

    WorkflowState get_state() const
    {
        std::lock_guard lk(mutex);
        return state;
    }

    WorkflowNodeProcess get_process() const
    {
        return process;
    }
};