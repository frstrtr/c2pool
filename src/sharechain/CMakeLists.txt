set(SHARECHAIN_SOURCE
    share.hpp
    sharechain.hpp
)

add_library(sharechain STATIC ${SHARECHAIN_SOURCE})
target_link_libraries(sharechain core)

add_subdirectory(test)