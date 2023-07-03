set(web_interface_source
        response_sender.h
        webnode.h
        webroot.h
        webserver.h
        webexcept.h
        session_interface.h
        webroot.cpp
        webnode.cpp
        response_sender.cpp)

add_library(web_interface ${web_interface_source})
#target_link_libraries(web_interface )