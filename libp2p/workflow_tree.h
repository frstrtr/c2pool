#pragma once
#include <thread>
#include <vector>
#include <mutex>
#include <memory>
#include <set>


#include <boost/asio.hpp>

#include "workflow_node.h"
#include "workflow_thread.h"

class WorkflowTree
{
    mutable std::mutex mutex;
    boost::asio::io_context* ctx;

    std::vector<WorkflowNode*> chain;
    std::unique_ptr<WorkflowThread> thread;

private:
    static void calculate_chain(WorkflowNode* node, std::vector<WorkflowNode*> &result_chain)
    {
        if (node == nullptr)
            return;

        result_chain.push_back(node);

        for (WorkflowNode* next : node->next)
            calculate_chain(next, result_chain);
    }

    static std::shared_ptr<RunWorkflowTask> make_run_task(WorkflowNode* node)
    {
        return std::make_shared<RunWorkflowTask>(
            [node](const std::shared_ptr<WorkflowTask>& task)
            {
                node->run(task);
            }
        );
    }
    
    // non-thread safe, call only from launch, cancel, restart, workflow!
    void run()
    {
        std::list<std::shared_ptr<WorkflowTask>> tasks;
        std::list<std::shared_ptr<WorkflowTask>> run_tasks;
        
        for (std::vector<WorkflowNode*>::reverse_iterator it = chain.rbegin(); it != chain.rend(); it++)
        {
            auto node = *it;
            std::lock_guard lk(node->mutex); // LOCK NODE

            switch (node->state)
            {
            case WorkflowState::processing_disconnect:
            {
                // make task for waiting stopping node
                auto stop_task = std::make_shared<StopWorkflowTask>();
                node->update_task(stop_task);
                tasks.push_back(stop_task);

                // re-run node task
                auto run_task = make_run_task(node);
                node->update_task(run_task);
                run_tasks.push_front(run_task);
                
                continue;
            }
            case WorkflowState::processing_connect:
                std::cout << "ERROR: run() -- node processing_connect!" << std::endl;
                break;
            case WorkflowState::disconnected:
            {
                // run
                auto run_task = make_run_task(node);
                node->update_task(run_task);

                run_tasks.push_front(run_task);
                break;
            }
            case WorkflowState::connected:
                break;
            default:
                std::cout << "Error: Workflow run -- why default?" << std::endl;
            }
        }
        
        // merge stop tasks + run tasks
        tasks.splice(tasks.end(), run_tasks);
        
        // add tasks to current thread
        thread->add_tasks(tasks);
    }

    // non-thread safe, call only from launch, cancel, restart!
    void stop(std::set<WorkflowNode*> chain_)
    {
        std::list<std::shared_ptr<WorkflowTask>> tasks;
        for(std::vector<WorkflowNode*>::reverse_iterator it = chain.rbegin(); it != chain.rend(); it++)
        {
            auto node = *it;
            std::unique_lock lk(node->mutex); // LOCK NODE

            switch (node->state)
            {
            case WorkflowState::connected:
                // skip node if we don’t need it to be skipped
                if (!chain_.contains(node))
                    continue;
                // continue in WorkflowState::processing_connect, if chain not contains node
            case WorkflowState::processing_connect:
            {
                auto stop_task = std::make_shared<StopWorkflowTask>();
                node->update_task(stop_task);
                tasks.push_back(stop_task);

                lk.unlock();
                node->stop(stop_task);
                
                break;
            }
            case WorkflowState::processing_disconnect:
            {
                auto stop_task = std::make_shared<StopWorkflowTask>();
                node->update_task(stop_task);
                tasks.push_back(stop_task);
                break;
            }
            case WorkflowState::disconnected:
                break;
            default:
                std::cout << "Error: Workflow stop -- why default?" << std::endl;
            }
        }

        // add tasks to current thread
        thread->add_tasks(tasks);
    }

    // WARNING!: called after stop()!
    // usally for restart()
    // non-thread safe, call only from launch, cancel, restart!
    void pure_run()
    {
        std::list<std::shared_ptr<WorkflowTask>> tasks;
        
        for (std::vector<WorkflowNode*>::reverse_iterator it = chain.rbegin(); it != chain.rend(); it++)
        {
            auto node = *it;
            std::lock_guard lk(node->mutex); // LOCK NODE

            switch (node->state)
            {
            case WorkflowState::processing_disconnect:
            case WorkflowState::disconnected:
            {
                // run
                auto run_task = make_run_task(node);
                node->update_task(run_task);

                tasks.push_front(run_task);
                break;
            }
            case WorkflowState::connected:
                break;
            default:
                std::cout << "Error: Workflow pure_run -- why default?" << std::endl;
            }
        }
        
        // add tasks to current thread
        thread->add_tasks(tasks);
    }

    // non-thread safe, call only from launch, cancel, restart!
    template <typename...F>
    void workflow(F&&... funcs)
    {
        // Cancel current workflow thread
        // TODO: WAIT FOR CANCEL PROCESS?
        if (thread)
        {
            thread->cancel();
            thread.reset();
        }

        // std::this_thread::sleep_for(std::chrono::seconds(1));

        // create new thread
        thread = std::make_unique<WorkflowThread>([&]{ thread.reset(); });

        // call all funcs: stop, run ...
        (std::invoke(funcs, this), ...);
        
        thread->start();
    }

public:
    WorkflowTree() = default;

    void init(boost::asio::io_context *ctx_, WorkflowNode *tree_start)
    {
        ctx = ctx_;
        // init tree chain
        calculate_chain(tree_start, chain);
    }

    // Launch all nodes
    void launch()
    {
        std::lock_guard lk(mutex);
        std::cout << "Launch" << std::endl;
        workflow(&WorkflowTree::run);    
    }

    // Just stop all nodes
    void cancel()
    {
        std::lock_guard lk(mutex);
        std::cout << "Cancel" << std::endl;
        workflow(
            [chain_ = std::set(chain.begin(), chain.end())](WorkflowTree* tree){ tree->stop(chain_); }
        );
    }

    // Restart tree from <node>
    void restart(WorkflowNode* node)
    {
        std::lock_guard lk(mutex);
        std::cout << "Restart" << std::endl;

        std::vector<WorkflowNode*> chain_;
        calculate_chain(node, chain_);

        workflow(
            [chain_ = std::set(std::make_move_iterator(chain_.begin()), 
                               std::make_move_iterator(chain_.end()))]
                (WorkflowTree* tree)
                { 
                    tree->stop(chain_); 
                },
            &WorkflowTree::pure_run
        );
    }
};