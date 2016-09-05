project(evosec)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Wextra -Werror -pedantic")
link_directories(/usr/local/Cellar/openssl/1.0.2h_1/lib/)
include_directories(/usr/local/Cellar/openssl/1.0.2h_1/include/ SYSTEM)
include_directories(/Users/emilchess/evosec_code/src/engine)
add_library(engine SHARED engine.cc)
target_link_libraries(engine crypto)

