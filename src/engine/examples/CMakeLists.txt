add_executable(main main.cpp)
message(WARNING "gotta: " ${CMAKE_LIBRARY_PATH})
target_link_libraries(main engine)
