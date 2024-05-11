#pragma once

#include <string>
#include <fstream>

#include <core/filesystem.hpp>
#include <core/log.hpp>

namespace c2pool
{

#define PARSE_CONFIG(node, field, type) \
    m_##field = node[#field].as<type>()

#define PARSE_OPTIONAL_CONFIG(node, field, type)  \
    if (node[#field])      \
        PARSE_CONFIG(node, field, type)

class fileconfig
{
    std::filesystem::path m_filepath;

protected:
    virtual std::string get_default() = 0;
    virtual void load() = 0;
    
public:
    fileconfig(std::filesystem::path filepath) : m_filepath(filepath)
    {

    }
    
    template <typename CONFIG_TYPE>
    static CONFIG_TYPE* load_file()
    {
        static_assert(std::is_base_of<fileconfig, CONFIG_TYPE>(), "CONFIG_TYPE in fileconfig::load_file not based from fileconfig");
        
        fileconfig* config = new CONFIG_TYPE();

        // check for exist path + make default
        if (!std::filesystem::exists(config->m_filepath))
        {
            std::filesystem::create_directory(config->m_filepath.parent_path());
        
            std::ofstream file(config->m_filepath);
            file << config->get_default();
            file.close();
            LOG_WARNING << "Config (" << config->m_filepath << "): not found, created default.";
        }

        // load from file
        config->load();
        
        return static_cast<CONFIG_TYPE*>(config);
    }
};
    
} // namespace c2pool
