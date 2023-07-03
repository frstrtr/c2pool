set(web_interface_source
        webroot.cpp webroot.h
        webnode.cpp webnode.h
        response_sender.h
        webserver.h
        webexcept.h
        session_interface.h
        response_sender.cpp)

add_library(web_interface ${web_interface_source})
#target_link_libraries(web_interface )