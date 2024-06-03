set(SHARECHAIN_SOURCE
    share.hpp
)

add_library(sharechain ${SHARECHAIN_SOURCE})
target_link_libraries(sharechain core)