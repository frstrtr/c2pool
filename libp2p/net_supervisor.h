#pragma once
#include <map>
#include <set>
#include <queue>

#include <libdevcore/logger.h>

enum net_state
{
    disconnected = 0,
    processing,
    connected
};

class SupervisorElement
{
    typedef std::function<void(SupervisorElement*)> finish_type;
    typedef std::function<void(SupervisorElement*, std::string)> restart_type;
private:
    // functor, called when finished reconnecting [NetSupervisor::finish_element]
    finish_type finish_reconnecting;
    // functor, called when need stop and reconnecting all network [NetSupervisor::restart]
    restart_type restart_network;
protected:
    net_state state {net_state::disconnected};
    uint8_t layer{};
public:
    SupervisorElement() = default;

    // finished reconnecting
    void reconnected()
    {
        finish_reconnecting(this);
    }
    
    // stop and reconnect all network
    void restart(const std::string& reason)
    {
        restart_network(this, reason);
    }

    net_state get_state() const
    {
        return state;
    }

    uint8_t get_layer() const
    {
        return layer;
    }

    void set_state(net_state new_state)
    {
        state = new_state;
    }

    bool is_connected() const
    {
        return state == connected;
    }

    bool is_available() const
    {
        return state != disconnected;
    }
public:
    // call once when initialize element
    void init_supervisor(uint8_t l, finish_type&& finish_func, restart_type&& restart_network_func) 
    {
        layer = l;
        finish_reconnecting = std::move(finish_func);
        restart_network = std::move(restart_network_func);
    }

    // called for disconnect
    virtual void stop() = 0;
    // 
    virtual void reconnect() = 0;
};

class NetSupervisor
{
protected:
    // Network layers [0; 2^8]
    std::map<uint8_t, std::set<SupervisorElement*>> layers; 
    // Container from which service reconnection occurs in the order of queue
    std::queue<SupervisorElement*> reconnect_queue;
    // Current element for reconnect
    SupervisorElement* current;
protected:
    // iterate reconnect_queue for reconnect();
    inline void next_queue()
    {
        // reconnect queue empty
        if (!reconnect_queue.size())
        {
            current = nullptr;
            return;
        }

        current = reconnect_queue.front();
        reconnect_queue.pop();

        current->set_state(processing);
        current->reconnect();
    }
public:
    void add(SupervisorElement* element, uint8_t layer)
    {
        if (!layers[element->get_layer()].count(element))
        {
            layers[element->get_layer()].insert(element);
            element->init_supervisor(
                layer, 
                [this](SupervisorElement* element){ finish_element(element); },
                [this](SupervisorElement* element, const std::string& reason){ restart(element, reason); }
            );
        }
        else
        {
            LOG_WARNING << "Element is already in " << element->get_layer() << " layer.";
        }
    }

    // Called when finished reconnect for element
    void finish_element(SupervisorElement* element)
    {
        if (!element)
        {
            throw std::invalid_argument("NetSupervisor::finish_element called for incorrect element");
        }
        
        element->set_state(connected);
        next_queue();
    }

    void restart(SupervisorElement* element, const std::string& reason)
    {
        //TODO: REASON
        std::queue<SupervisorElement*> new_reconnect_queue;

        // Stop all supervisor elements upper.
        auto layer_it = layers.find(element->get_layer());
        while (layer_it != layers.end())
        {
            for (auto& el : layer_it->second)
            {
                new_reconnect_queue.push(el);
                el->stop();
            }
            layer_it++;
        }

        // Start reconnect again
        std::swap(reconnect_queue, new_reconnect_queue);

        next_queue();
    }
};