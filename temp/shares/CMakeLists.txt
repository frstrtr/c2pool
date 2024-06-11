add_executable(sharechain1 sharechain1.cpp)
target_link_libraries(sharechain1 core sharechain)

add_executable(chain_test chain_test.cpp)
target_link_libraries(chain_test core sharechain)