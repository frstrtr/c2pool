#pragma once
#include <map>
#include <set>
#include <stack>

#include <libdevcore/logger.h>

enum net_state
{
    disconnected = 0,
    disconnecting, // in progress to disconnect
    processing, // in progress to connect
    connected
};

class ConnectionStatus 
{
protected:
    net_state state {net_state::disconnected};
public:
    net_state get_state() const
    {
        return state;
    }

    void set_state(net_state new_state)
    {
        state = new_state;
    }

    bool is_available() const
    {
        return state != disconnected && state != disconnecting;
    }

    bool is_connected() const
    {
        return state == connected;
    }
};

class SupervisorElement : public ConnectionStatus
{
    typedef std::function<void(SupervisorElement*)> finish_type;
    typedef std::function<void(SupervisorElement*)> restart_type;

    // functor, called when finished reconnecting [NetSupervisor::finish_element]
    finish_type finish_reconnecting;
    // functor, called when need stop and reconnecting all network [NetSupervisor::restart]
    restart_type restart_network;
protected:
    uint8_t layer{};
public:
    SupervisorElement() = default;

    // finished reconnecting
    void reconnected()
    {
        finish_reconnecting(this);
    }
    
    // stop and reconnect all network
    void restart()
    {
        restart_network(this);
    }

    uint8_t get_layer() const
    {
        return layer;
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
    // called for reconnect, when element disconnected
    virtual void reconnect() = 0;
};

class NetSupervisor
{
protected:
    // Network layers [0; 2^8]
    std::map<uint8_t, std::set<SupervisorElement*>> layers; 
    // Container from which service reconnection occurs in the order of stack
    std::stack<SupervisorElement*> reconnect_elements;
    // Current element for reconnect
    SupervisorElement* current;
protected:
    // iterate reconnect_elements for reconnect();
    inline void next_element()
    {
        if (reconnect_elements.empty())
        {
            current = nullptr;
            return;
        }

        current = reconnect_elements.top();
        reconnect_elements.pop();

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
                [this](SupervisorElement* element){ restart(element); }
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
        next_element();
    }

    void restart(SupervisorElement* element)
    {
        LOG_INFO << "Restart network from layer = " << element->get_layer();
        std::stack<SupervisorElement*> new_reconnect_elements;

        // Stop all supervisor elements upper.
        auto last_layer = element->get_layer();
        for (auto layer_it = layers.rbegin(); layer_it != layers.rend(); layer_it++)
        {
            for (auto& el : layer_it->second)
            {
                new_reconnect_elements.push(el);
                el->set_state(disconnecting);
                el->stop();
            }
            
            // layer_it == element->layer
            if (last_layer == layer_it->first)
                break;
        }

        // Start reconnect again
        std::swap(reconnect_elements, new_reconnect_elements);

        next_element();
    }
};